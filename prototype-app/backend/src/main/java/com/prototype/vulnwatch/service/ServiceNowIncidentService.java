package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.ServiceNowAuthType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CreateServiceNowIncidentRequest;
import com.prototype.vulnwatch.dto.ServiceNowIncidentResponse;
import com.prototype.vulnwatch.repo.FindingRepository;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import static org.springframework.http.HttpStatus.BAD_GATEWAY;
import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE;

@Service
public class ServiceNowIncidentService {

    private static final Logger log = LoggerFactory.getLogger(ServiceNowIncidentService.class);
    private static final String DEFAULT_ASSIGNMENT_GROUP = "App-Sec Manager";

    /** Maps ServiceNow incident state codes to human-readable labels. */
    public static final Map<String, String> SNOW_STATE_LABELS = Map.of(
            "1", "New",
            "2", "In Progress",
            "3", "On Hold",
            "6", "Resolved",
            "7", "Closed",
            "8", "Canceled"
    );

    private static final Map<String, Integer> PRIORITY_MAP = Map.of(
            "CRITICAL", 1,
            "HIGH",     2,
            "MEDIUM",   3,
            "LOW",      4
    );

    private final ServiceNowCmdbConfigService serviceNowCmdbConfigService;
    private final OutboundHttpClient outboundHttpClient;
    private final OutboundPolicyFactory outboundPolicyFactory;
    private final ObjectMapper objectMapper;
    private final FindingRepository findingRepository;

    public ServiceNowIncidentService(
            ServiceNowCmdbConfigService serviceNowCmdbConfigService,
            OutboundHttpClient outboundHttpClient,
            OutboundPolicyFactory outboundPolicyFactory,
            ObjectMapper objectMapper,
            FindingRepository findingRepository
    ) {
        this.serviceNowCmdbConfigService = serviceNowCmdbConfigService;
        this.outboundHttpClient = outboundHttpClient;
        this.outboundPolicyFactory = outboundPolicyFactory;
        this.objectMapper = objectMapper;
        this.findingRepository = findingRepository;
    }

    /** Creates and links an incident for a canonical non-CVE finding, including AI Grid findings. */
    @Transactional
    public ServiceNowIncidentResponse createFindingIncident(
            Tenant tenant,
            UUID findingId,
            CreateServiceNowIncidentRequest request
    ) {
        ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config = resolveIncidentConfig(tenant);
        Finding finding = findingRepository.findById(findingId)
                .orElseThrow(() -> new org.springframework.web.server.ResponseStatusException(
                        org.springframework.http.HttpStatus.NOT_FOUND, "Finding not found"));
        assertFindingEligibleForIncident(finding);

        ServiceNowIncidentResponse response = createFindingIncidentRemote(config, finding, request);
        finding.setIncidentId(response.incidentNumber());
        finding.setIncidentStatus("New");
        finding.touch();
        findingRepository.save(finding);
        return response;
    }

    /** Resolves the tenant's ServiceNow connector, or fails with the operator-facing 503. */
    public ServiceNowCmdbConfigService.ServiceNowRuntimeConfig resolveIncidentConfig(Tenant tenant) {
        return serviceNowCmdbConfigService.resolveRuntimeConfig(tenant)
                .orElseThrow(() -> new ResponseStatusException(
                        SERVICE_UNAVAILABLE,
                        "ServiceNow is not configured for this tenant. Configure the ServiceNow connector first."
                ));
    }

    /** A closed finding must not acquire a fresh incident — the remediation is already done. */
    public void assertFindingEligibleForIncident(Finding finding) {
        if (finding.getStatus() == com.prototype.vulnwatch.domain.FindingStatus.RESOLVED
                || finding.getStatus() == com.prototype.vulnwatch.domain.FindingStatus.AUTO_CLOSED) {
            throw new ResponseStatusException(CONFLICT, "Closed findings are not eligible for a new incident");
        }
    }

    /**
     * Raises the incident in ServiceNow and returns it <em>without</em> writing to the finding.
     *
     * <p>Split out so {@link com.prototype.vulnwatch.ticketing.ServiceNowTicketingProvider} can
     * reuse the exact payload and error handling while
     * {@link com.prototype.vulnwatch.ticketing.TicketingService} owns the finding update — that
     * keeps the incident id, status and originating system written together for every provider.
     */
    public ServiceNowIncidentResponse createFindingIncidentRemote(
            ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config,
            Finding finding,
            CreateServiceNowIncidentRequest request
    ) {
        String severity = text(request.severity(), finding.getSeverityOverride(), riskSeverity(finding.getRiskScore()));
        String priorityLabel = text(request.priority(), severity, "MEDIUM");
        int priority = PRIORITY_MAP.getOrDefault(priorityLabel.toUpperCase(Locale.ROOT), 3);
        String assignmentGroup = text(finding.getOwnerGroup(), DEFAULT_ASSIGNMENT_GROUP);
        String dueDate = text(request.dueDate(), isoDate(finding.getDueAt()));
        String title = text(request.findingTitle(), finding.getTitle(), finding.getDisplayId());

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("short_description", finding.getDisplayId() + ": " + title);
        payload.put("description", buildFindingDescription(finding, severity, request, dueDate));
        payload.put("work_notes", "Scout AI Security finding " + finding.getDisplayId()
                + " was promoted to the canonical remediation workflow.");
        payload.put("priority", String.valueOf(priority));
        payload.put("urgency", String.valueOf(Math.min(3, priority)));
        payload.put("impact", String.valueOf(Math.min(3, priority)));
        payload.put("category", "Security");
        payload.put("subcategory", "Vulnerability");
        payload.put("assignment_group", assignmentGroup);
        if (request.assignedTo() != null && !request.assignedTo().isBlank()) {
            payload.put("assigned_to", request.assignedTo().trim());
        }
        if (dueDate != null) payload.put("due_date", dueDate + " 00:00:00");
        if (request.solutionInfo() != null && !request.solutionInfo().isBlank()) {
            payload.put("close_notes", request.solutionInfo().trim());
        }

        String body;
        try { body = objectMapper.writeValueAsString(payload); }
        catch (JsonProcessingException e) {
            throw new ResponseStatusException(BAD_GATEWAY, "Failed to serialize incident payload: " + e.getMessage());
        }
        ResponseEntity<String> response = outboundHttpClient.exchange(
                config.baseUrl() + "/api/now/table/incident", HttpMethod.POST,
                new HttpEntity<>(body, buildJsonHeaders(config)), String.class,
                "ServiceNow finding incident creation",
                outboundPolicyFactory.forProvider("servicenow", 0L, null, null),
                context -> new OutboundFailureDecision<>(
                        context.isRetryableByDefault(), context.retryAfterDelayMs(),
                        context.error() instanceof RuntimeException rte ? rte
                                : new RuntimeException("ServiceNow incident creation failed: "
                                + context.error().getMessage(), context.error())));
        JsonNode result = ServiceNowApiResponseParser.parseJson(
                objectMapper, response, "ServiceNow finding incident creation").path("result");
        String incidentNumber = result.path("number").asText(null);
        String sysId = result.path("sys_id").asText(null);
        if (incidentNumber == null || incidentNumber.isBlank()) {
            throw new ResponseStatusException(BAD_GATEWAY,
                    "ServiceNow returned an unexpected response — incident number missing");
        }
        String taskDueDate = text(request.taskSlaDueDate(), dueDate);
        if (sysId != null && !sysId.isBlank() && taskDueDate != null) {
            createTaskSla(config, sysId, taskDueDate);
        }
        return new ServiceNowIncidentResponse(incidentNumber, sysId,
                config.baseUrl() + "/incident.do?sys_id=" + sysId, "created",
                "Incident " + incidentNumber + " created successfully in ServiceNow");
    }

    /**
     * Fetches the current state of a ServiceNow incident by incident number.
     * Returns the human-readable label (e.g. "Resolved") or null if not found.
     */
    public String getIncidentStatus(ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config, String incidentNumber) {
        String endpoint = config.baseUrl()
                + "/api/now/table/incident?sysparm_query=number%3D" + incidentNumber
                + "&sysparm_fields=number%2Cstate&sysparm_limit=1";

        HttpHeaders headers = buildHeaders(config);
        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);

        try {
            ResponseEntity<String> response = outboundHttpClient.exchange(
                    endpoint,
                    HttpMethod.GET,
                    requestEntity,
                    String.class,
                    "ServiceNow incident status fetch",
                    outboundPolicyFactory.forProvider("servicenow", 0L, null, null),
                    context -> new OutboundFailureDecision<>(
                            context.isRetryableByDefault(),
                            context.retryAfterDelayMs(),
                            context.error() instanceof RuntimeException rte ? rte
                                    : new RuntimeException("ServiceNow status fetch failed: " + context.error().getMessage(), context.error())
                    )
            );

            JsonNode root = ServiceNowApiResponseParser.parseJson(objectMapper, response, "ServiceNow incident status fetch");
            JsonNode resultArray = root.path("result");
            if (resultArray.isArray() && !resultArray.isEmpty()) {
                String stateCode = resultArray.get(0).path("state").asText(null);
                if (stateCode != null) {
                    return SNOW_STATE_LABELS.getOrDefault(stateCode, "Unknown (" + stateCode + ")");
                }
            }
        } catch (Exception e) {
            log.warn("Failed to fetch ServiceNow status for incident {}: {}", incidentNumber, e.getMessage());
        }
        return null;
    }

    /** ServiceNow state codes that mean the remediation work is finished. */
    public static final java.util.Set<String> SNOW_RESOLVED_STATE_CODES = java.util.Set.of("6", "7");

    /**
     * Creates one incident for a CVE and an already-grouped set of assets, without touching
     * findings. {@link com.prototype.vulnwatch.ticketing.TicketingService} owns the grouping
     * and the finding linkage.
     */
    public ServiceNowIncidentResponse createCveIncidentRemote(
            ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config,
            String cveId,
            CreateServiceNowIncidentRequest request,
            String effectiveAssignmentGroup,
            List<CreateServiceNowIncidentRequest.AffectedAsset> groupAssets
    ) {
        return createSingleIncident(config, cveId, request, effectiveAssignmentGroup, groupAssets);
    }

    /**
     * Raw {@code state} code for an incident, or empty when it cannot be read.
     *
     * <p>Returns the code rather than the label so the caller can decide what counts as
     * resolved. {@link #SNOW_STATE_LABELS} turns it into operator-facing wording.
     */
    public Optional<String> fetchIncidentStateCode(
            ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config,
            String incidentNumber
    ) {
        if (incidentNumber == null || incidentNumber.isBlank()) {
            return Optional.empty();
        }
        String endpoint = config.baseUrl()
                + "/api/now/table/incident?sysparm_query=number%3D"
                + java.net.URLEncoder.encode(incidentNumber.trim(), StandardCharsets.UTF_8)
                + "&sysparm_fields=number%2Cstate&sysparm_limit=1";
        try {
            ResponseEntity<String> response = outboundHttpClient.exchange(
                    endpoint, HttpMethod.GET, new HttpEntity<Void>(buildHeaders(config)), String.class,
                    "ServiceNow incident status fetch",
                    outboundPolicyFactory.forProvider("servicenow", 0L, null, null),
                    context -> new OutboundFailureDecision<RuntimeException>(
                            context.isRetryableByDefault(), context.retryAfterDelayMs(),
                            context.error() instanceof RuntimeException rte ? rte
                                    : new RuntimeException("ServiceNow status fetch failed: "
                                    + context.error().getMessage(), context.error())));
            JsonNode result = ServiceNowApiResponseParser
                    .parseJson(objectMapper, response, "ServiceNow incident status fetch").path("result");
            if (result.isArray() && !result.isEmpty()) {
                String stateCode = result.get(0).path("state").asText(null);
                if (stateCode != null && !stateCode.isBlank()) {
                    return Optional.of(stateCode);
                }
            }
        } catch (Exception e) {
            log.warn("Failed to fetch ServiceNow state for incident {}: {}", incidentNumber, e.getMessage());
        }
        return Optional.empty();
    }

    /**
     * Applies field updates to an incident identified by number.
     *
     * <p>The Table API updates by sys_id, and findings store the human-facing incident number,
     * so this resolves the sys_id first. Returns false rather than throwing: a single ticket
     * that cannot be updated must not abort a sync covering every other ticket.
     */
    public boolean updateIncidentByNumber(
            ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config,
            String incidentNumber,
            Map<String, Object> fields
    ) {
        if (incidentNumber == null || incidentNumber.isBlank() || fields == null || fields.isEmpty()) {
            return false;
        }
        Optional<String> sysId = fetchIncidentSysId(config, incidentNumber);
        if (sysId.isEmpty()) {
            log.warn("Cannot update ServiceNow incident {} — sys_id could not be resolved", incidentNumber);
            return false;
        }
        String body;
        try {
            body = objectMapper.writeValueAsString(fields);
        } catch (JsonProcessingException e) {
            log.warn("Failed to serialize ServiceNow update for incident {}: {}", incidentNumber, e.getMessage());
            return false;
        }
        try {
            ResponseEntity<String> response = outboundHttpClient.exchange(
                    config.baseUrl() + "/api/now/table/incident/" + sysId.get(),
                    HttpMethod.PATCH,
                    new HttpEntity<>(body, buildJsonHeaders(config)),
                    String.class,
                    "ServiceNow incident update",
                    outboundPolicyFactory.forProvider("servicenow", 0L, null, null),
                    context -> new OutboundFailureDecision<RuntimeException>(
                            context.isRetryableByDefault(), context.retryAfterDelayMs(),
                            context.error() instanceof RuntimeException rte ? rte
                                    : new RuntimeException("ServiceNow incident update failed: "
                                    + context.error().getMessage(), context.error())));
            return response.getStatusCode().is2xxSuccessful();
        } catch (Exception e) {
            log.warn("Failed to update ServiceNow incident {}: {}", incidentNumber, e.getMessage());
            return false;
        }
    }

    private Optional<String> fetchIncidentSysId(
            ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config,
            String incidentNumber
    ) {
        String endpoint = config.baseUrl()
                + "/api/now/table/incident?sysparm_query=number%3D"
                + java.net.URLEncoder.encode(incidentNumber.trim(), StandardCharsets.UTF_8)
                + "&sysparm_fields=sys_id&sysparm_limit=1";
        try {
            ResponseEntity<String> response = outboundHttpClient.exchange(
                    endpoint, HttpMethod.GET, new HttpEntity<Void>(buildHeaders(config)), String.class,
                    "ServiceNow incident sys_id lookup",
                    outboundPolicyFactory.forProvider("servicenow", 0L, null, null),
                    context -> new OutboundFailureDecision<RuntimeException>(
                            context.isRetryableByDefault(), context.retryAfterDelayMs(),
                            context.error() instanceof RuntimeException rte ? rte
                                    : new RuntimeException("ServiceNow sys_id lookup failed: "
                                    + context.error().getMessage(), context.error())));
            JsonNode result = ServiceNowApiResponseParser
                    .parseJson(objectMapper, response, "ServiceNow incident sys_id lookup").path("result");
            if (result.isArray() && !result.isEmpty()) {
                String value = result.get(0).path("sys_id").asText(null);
                if (value != null && !value.isBlank()) {
                    return Optional.of(value);
                }
            }
        } catch (Exception e) {
            log.warn("Failed to resolve sys_id for ServiceNow incident {}: {}", incidentNumber, e.getMessage());
        }
        return Optional.empty();
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    private ServiceNowIncidentResponse createSingleIncident(
            ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config,
            String cveId,
            CreateServiceNowIncidentRequest req,
            String effectiveAssignmentGroup,
            List<CreateServiceNowIncidentRequest.AffectedAsset> groupAssets
    ) {
        Map<String, Object> payload = buildPayload(cveId, req, effectiveAssignmentGroup, groupAssets);

        String body;
        try {
            body = objectMapper.writeValueAsString(payload);
        } catch (JsonProcessingException e) {
            throw new ResponseStatusException(BAD_GATEWAY, "Failed to serialize incident payload: " + e.getMessage());
        }

        HttpHeaders headers = buildHeaders(config);
        headers.setContentType(MediaType.APPLICATION_JSON);

        String endpoint = config.baseUrl() + "/api/now/table/incident";
        HttpEntity<String> requestEntity = new HttpEntity<>(body, headers);

        ResponseEntity<String> response = outboundHttpClient.exchange(
                endpoint,
                HttpMethod.POST,
                requestEntity,
                String.class,
                "ServiceNow incident creation",
                outboundPolicyFactory.forProvider("servicenow", 0L, null, null),
                context -> new OutboundFailureDecision<>(
                        context.isRetryableByDefault(),
                        context.retryAfterDelayMs(),
                        context.error() instanceof RuntimeException rte ? rte
                                : new RuntimeException("ServiceNow incident creation failed: " + context.error().getMessage(), context.error())
                )
        );

        JsonNode root = ServiceNowApiResponseParser.parseJson(objectMapper, response, "ServiceNow incident creation");
        JsonNode result = root.path("result");

        String incidentNumber = result.path("number").asText(null);
        String sysId = result.path("sys_id").asText(null);

        if (incidentNumber == null || incidentNumber.isBlank()) {
            throw new ResponseStatusException(BAD_GATEWAY, "ServiceNow returned an unexpected response — incident number missing");
        }

        // Associate additional CIs via the task_ci M2M table (skip the primary already on cmdb_ci)
        if (sysId != null && !sysId.isBlank()) {
            String primaryCiSysId = groupAssets.stream()
                    .map(a -> extractCiSysId(a.assetIdentifier()))
                    .filter(id -> id != null)
                    .findFirst()
                    .orElse(null);
            linkAdditionalCis(config, sysId, primaryCiSysId, groupAssets);
            // Create a Task SLA record for the remediation due date
            if (req.taskSlaDueDate() != null && !req.taskSlaDueDate().isBlank()) {
                createTaskSla(config, sysId, req.taskSlaDueDate());
            }
        }

        String url = config.baseUrl() + "/incident.do?sys_id=" + sysId;
        return new ServiceNowIncidentResponse(
                incidentNumber,
                sysId,
                url,
                "created",
                "Incident " + incidentNumber + " created successfully in ServiceNow"
        );
    }

    private HttpHeaders buildJsonHeaders(ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config) {
        HttpHeaders headers = buildHeaders(config);
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }

    private String buildFindingDescription(Finding finding, String severity,
                                           CreateServiceNowIncidentRequest request, String dueDate) {
        StringBuilder description = new StringBuilder("AI SECURITY FINDING\n===================\n");
        description.append("Finding ID : ").append(finding.getDisplayId()).append('\n');
        description.append("Title      : ").append(text(finding.getTitle(), "AI security finding")).append('\n');
        description.append("Severity   : ").append(severity).append('\n');
        if (finding.getPolicyId() != null) description.append("Policy     : ").append(finding.getPolicyId()).append('\n');
        if (finding.getReasonCode() != null) description.append("Reason     : ").append(finding.getReasonCode()).append('\n');
        if (dueDate != null) description.append("Due date   : ").append(dueDate).append('\n');
        if (request.solutionInfo() != null && !request.solutionInfo().isBlank()) {
            description.append("\nREMEDIATION\n===========\n").append(request.solutionInfo().trim()).append('\n');
        }
        if (request.notes() != null && !request.notes().isBlank()) {
            description.append("\nANALYST NOTES\n=============\n").append(request.notes().trim()).append('\n');
        }
        return description.toString();
    }

    private String riskSeverity(double score) {
        if (score >= 9) return "CRITICAL";
        if (score >= 7) return "HIGH";
        if (score >= 4) return "MEDIUM";
        return "LOW";
    }

    private String isoDate(java.time.Instant instant) {
        return instant == null ? null : java.time.format.DateTimeFormatter.ISO_LOCAL_DATE
                .withZone(java.time.ZoneOffset.UTC).format(instant);
    }

    private String text(String... values) {
        for (String value : values) if (value != null && !value.isBlank()) return value.trim();
        return null;
    }

    /**
     * Links additional CIs in the group to the incident via the {@code task_ci} M2M table.
     * The primary CI is already set via {@code cmdb_ci} on the incident; skip it here to
     * avoid a duplicate-insert 403 from ServiceNow.
     */
    private void linkAdditionalCis(
            ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config,
            String incidentSysId,
            String primaryCiSysId,
            List<CreateServiceNowIncidentRequest.AffectedAsset> groupAssets
    ) {
        String endpoint = config.baseUrl() + "/api/now/table/task_ci";
        HttpHeaders headers = buildHeaders(config);
        headers.setContentType(MediaType.APPLICATION_JSON);

        for (CreateServiceNowIncidentRequest.AffectedAsset asset : groupAssets) {
            String ciSysId = extractCiSysId(asset.assetIdentifier());
            if (ciSysId == null) continue;
            // The primary CI is already linked via cmdb_ci on the incident — skip it.
            if (ciSysId.equals(primaryCiSysId)) continue;

            Map<String, Object> taskCiPayload = new LinkedHashMap<>();
            taskCiPayload.put("task", incidentSysId);
            taskCiPayload.put("ci_item", ciSysId);

            try {
                String body = objectMapper.writeValueAsString(taskCiPayload);
                HttpEntity<String> requestEntity = new HttpEntity<>(body, headers);
                outboundHttpClient.exchange(
                        endpoint,
                        HttpMethod.POST,
                        requestEntity,
                        String.class,
                        "ServiceNow task_ci association",
                        outboundPolicyFactory.forProvider("servicenow", 0L, null, null),
                        context -> new OutboundFailureDecision<>(
                                false,
                                0L,
                                context.error() instanceof RuntimeException rte ? rte
                                        : new RuntimeException(context.error().getMessage(), context.error())
                        )
                );
            } catch (Exception e) {
                log.warn("Failed to associate CI {} with incident {}: {}", ciSysId, incidentSysId, e.getMessage());
            }
        }
    }

    /**
     * Creates a Task SLA record in ServiceNow linking the incident to a remediation target date.
     * Uses the {@code task_sla} table. Best-effort — failures are logged and do not abort incident creation.
     */
    private void createTaskSla(
            ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config,
            String incidentSysId,
            String dueDateYmd
    ) {
        String endpoint = config.baseUrl() + "/api/now/table/task_sla";
        HttpHeaders headers = buildHeaders(config);
        headers.setContentType(MediaType.APPLICATION_JSON);

        // Target date: YYYY-MM-DD 00:00:00 (ServiceNow datetime format)
        String targetDate = dueDateYmd.trim() + " 00:00:00";

        Map<String, Object> slaPayload = new LinkedHashMap<>();
        slaPayload.put("task", incidentSysId);
        slaPayload.put("target_date", targetDate);
        slaPayload.put("planned_end_date", targetDate);
        // Stage: in_progress so it appears as an active SLA commitment
        slaPayload.put("stage", "in_progress");

        try {
            String body = objectMapper.writeValueAsString(slaPayload);
            HttpEntity<String> requestEntity = new HttpEntity<>(body, headers);
            outboundHttpClient.exchange(
                    endpoint,
                    HttpMethod.POST,
                    requestEntity,
                    String.class,
                    "ServiceNow task_sla creation",
                    outboundPolicyFactory.forProvider("servicenow", 0L, null, null),
                    context -> new OutboundFailureDecision<>(
                            false,
                            0L,
                            context.error() instanceof RuntimeException rte ? rte
                                    : new RuntimeException(context.error().getMessage(), context.error())
                    )
            );
            log.info("Created task_sla for incident {} with target date {}", incidentSysId, targetDate);
        } catch (Exception e) {
            log.warn("Failed to create task_sla for incident {}: {}", incidentSysId, e.getMessage());
        }
    }

    private Map<String, Object> buildPayload(
            String cveId,
            CreateServiceNowIncidentRequest req,
            String effectiveAssignmentGroup,
            List<CreateServiceNowIncidentRequest.AffectedAsset> groupAssets
    ) {
        int priority = PRIORITY_MAP.getOrDefault(
                req.priority() != null ? req.priority().toUpperCase(Locale.ROOT) : "MEDIUM",
                3
        );

        String softwareLabel = deriveSoftwareLabel(groupAssets);
        String shortDescription = cveId + ": " + softwareLabel + ": Fix";
        String description = buildDescription(cveId, req, groupAssets);
        String workNotes = buildWorkNotes(cveId, req, effectiveAssignmentGroup, groupAssets);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("short_description", shortDescription);
        payload.put("description", description);
        payload.put("work_notes", workNotes);
        payload.put("priority", String.valueOf(priority));
        payload.put("urgency", String.valueOf(Math.min(3, priority)));
        payload.put("impact", String.valueOf(Math.min(3, priority)));
        payload.put("category", "Security");
        payload.put("subcategory", "Vulnerability");

        // Assignment group (always set — falls back to default)
        payload.put("assignment_group", effectiveAssignmentGroup);
        String assignedTo = req.assignedTo();
        if (assignedTo != null && !assignedTo.isBlank()) {
            payload.put("assigned_to", assignedTo.trim());
        }

        // Due date
        if (req.dueDate() != null && !req.dueDate().isBlank()) {
            payload.put("due_date", req.dueDate().trim() + " 00:00:00");
        }

        // Resolution notes: patch / fix information
        if (req.solutionInfo() != null && !req.solutionInfo().isBlank()) {
            payload.put("close_notes", req.solutionInfo().trim());
        }

        // Primary CI reference — first asset's sys_id (cmdb_ci resolves by sys_id in ServiceNow)
        String primaryCiSysId = groupAssets.stream()
                .map(a -> extractCiSysId(a.assetIdentifier()))
                .filter(id -> id != null)
                .findFirst()
                .orElse(null);
        if (primaryCiSysId != null) {
            payload.put("cmdb_ci", primaryCiSysId);
        }

        // Scout metadata custom fields
        payload.put("u_scout_cve_id", cveId);
        payload.put("u_scout_severity", req.severity() != null ? req.severity() : "");
        payload.put("u_scout_cvss_score", req.cvssScore() != null ? String.valueOf(req.cvssScore()) : "");
        payload.put("u_scout_kev", req.inKev() ? "true" : "false");

        return payload;
    }

    /**
     * Extracts the ServiceNow CI sys_id from an assetIdentifier.
     * Handles identifiers with a {@code ci:} prefix (e.g. {@code ci:0da9a80d3790...} → {@code 0da9a80d3790...}).
     */
    private String extractCiSysId(String assetIdentifier) {
        if (assetIdentifier == null || assetIdentifier.isBlank()) return null;
        String trimmed = assetIdentifier.trim();
        if (trimmed.startsWith("ci:")) {
            String sysId = trimmed.substring(3).trim();
            return sysId.isBlank() ? null : sysId;
        }
        // If it looks like a bare sys_id (32 hex chars), use it directly
        if (trimmed.matches("[0-9a-fA-F]{32}")) {
            return trimmed;
        }
        return null;
    }

    /** Returns a comma-separated list of distinct package names found in the asset group. */
    private String deriveSoftwareLabel(List<CreateServiceNowIncidentRequest.AffectedAsset> groupAssets) {
        List<String> names = groupAssets.stream()
                .map(CreateServiceNowIncidentRequest.AffectedAsset::packageName)
                .filter(n -> n != null && !n.isBlank())
                .distinct()
                .collect(Collectors.toList());
        if (names.isEmpty()) return "Unknown Software";
        return String.join(", ", names);
    }

    private String buildDescription(
            String cveId,
            CreateServiceNowIncidentRequest req,
            List<CreateServiceNowIncidentRequest.AffectedAsset> groupAssets
    ) {
        StringBuilder sb = new StringBuilder();
        sb.append("VULNERABILITY DETAILS\n");
        sb.append("=====================\n");
        sb.append("CVE ID       : ").append(cveId).append("\n");
        if (req.severity() != null) {
            sb.append("Severity     : ").append(req.severity()).append("\n");
        }
        if (req.cvssScore() != null) {
            sb.append("CVSS v3 Score: ").append(req.cvssScore()).append("\n");
        }
        if (req.epssScore() != null) {
            sb.append("EPSS Score   : ").append(String.format("%.1f%%", req.epssScore() * 100)).append("\n");
        }
        if (req.inKev()) {
            sb.append("CISA KEV     : YES — actively exploited, remediation required\n");
        }
        if (req.findingTitle() != null && !req.findingTitle().isBlank()) {
            sb.append("\nFINDING\n");
            sb.append("=======\n");
            sb.append(req.findingTitle().trim()).append("\n");
        }

        // Affected CIs — name with CI identifier so responders can look up in CMDB
        if (!groupAssets.isEmpty()) {
            sb.append("\nAFFECTED ASSETS (").append(groupAssets.size()).append(")\n");
            sb.append("================").append("=".repeat(String.valueOf(groupAssets.size()).length() + 3)).append("\n");
            for (CreateServiceNowIncidentRequest.AffectedAsset asset : groupAssets) {
                sb.append("  • ");
                if (asset.assetName() != null && !asset.assetName().isBlank()) {
                    sb.append(asset.assetName());
                }
                // Always include the CI identifier so responders can cross-reference CMDB
                if (asset.assetIdentifier() != null && !asset.assetIdentifier().isBlank()) {
                    sb.append(" (").append(asset.assetIdentifier()).append(")");
                }
                if (asset.packageName() != null) {
                    sb.append(" — ").append(asset.packageName());
                    if (asset.packageVersion() != null && !asset.packageVersion().isBlank()) {
                        sb.append(" ").append(asset.packageVersion());
                    }
                }
                sb.append("\n");
            }
        }

        if (req.dueDate() != null && !req.dueDate().isBlank()) {
            sb.append("\nREMEDIATION TARGET: ").append(req.dueDate()).append("\n");
        }

        // Solution / remediation guidance in the description body
        if (req.solutionInfo() != null && !req.solutionInfo().isBlank()) {
            sb.append("\nREMEDIATION PLAN\n");
            sb.append("================\n");
            sb.append(req.solutionInfo().trim()).append("\n");
        }

        if (req.notes() != null && !req.notes().isBlank()) {
            sb.append("\nANALYST NOTES\n");
            sb.append("=============\n");
            sb.append(req.notes().trim()).append("\n");
        }
        return sb.toString();
    }

    private String buildWorkNotes(
            String cveId,
            CreateServiceNowIncidentRequest req,
            String effectiveAssignmentGroup,
            List<CreateServiceNowIncidentRequest.AffectedAsset> groupAssets
    ) {
        StringBuilder sb = new StringBuilder();
        sb.append("Scout Finding — created automatically by Scout vulnerability management platform.\n\n");
        sb.append("CVE: ").append(cveId).append("\n");
        if (req.priority() != null) sb.append("Priority: ").append(req.priority()).append("\n");
        sb.append("Assignment Group: ").append(effectiveAssignmentGroup).append("\n");

        if (!groupAssets.isEmpty()) {
            sb.append("\nAffected CIs:\n");
            groupAssets.forEach(a -> {
                sb.append("  • ");
                if (a.assetName() != null && !a.assetName().isBlank()) {
                    sb.append(a.assetName());
                }
                if (a.assetIdentifier() != null && !a.assetIdentifier().isBlank()) {
                    sb.append(" (").append(a.assetIdentifier()).append(")");
                }
                sb.append("\n");
            });
            sb.append("\nAffected component IDs:\n");
            groupAssets.forEach(a -> sb.append("  ").append(a.componentId()).append("\n"));
        }

        if (req.solutionInfo() != null && !req.solutionInfo().isBlank()) {
            sb.append("\nREMEDIATION / SOLUTION\n");
            sb.append("======================\n");
            sb.append(req.solutionInfo().trim()).append("\n");
        }

        return sb.toString();
    }

    /**
     * Fetches the list of active assignment group names from ServiceNow's sys_user_group table.
     * Returns an empty list if ServiceNow is not configured or the call fails.
     */
    public List<String> listAssignmentGroups(Tenant tenant) {
        ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config =
                serviceNowCmdbConfigService.resolveRuntimeConfig(tenant).orElse(null);
        if (config == null) {
            log.debug("ServiceNow not configured, skipping assignment group fetch");
            return List.of();
        }
        try {
            String url = config.baseUrl().replaceAll("/+$", "")
                    + "/api/now/table/sys_user_group"
                    + "?sysparm_fields=name,description"
                    + "&sysparm_query=active%3Dtrue"
                    + "&sysparm_limit=500"
                    + "&sysparm_display_value=true"
                    + "&sysparm_exclude_reference_link=true";
            ResponseEntity<String> response = outboundHttpClient.exchange(
                    url,
                    HttpMethod.GET,
                    new HttpEntity<>(buildHeaders(config)),
                    String.class,
                    "ServiceNow sys_user_group",
                    outboundPolicyFactory.forProvider("servicenow", 0L, null, null),
                    context -> new OutboundFailureDecision<>(context.isRetryableByDefault(), context.retryAfterDelayMs(),
                            context.error() instanceof RuntimeException re ? re : new RuntimeException(context.error()))
            );
            if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
                return List.of();
            }
            JsonNode root = ServiceNowApiResponseParser.parseJson(objectMapper, response, "ServiceNow sys_user_group");
            JsonNode results = root.path("result");
            if (!results.isArray()) return List.of();
            List<String> groups = new ArrayList<>();
            for (JsonNode node : results) {
                String name = node.path("name").asText(null);
                if (name != null && !name.isBlank()) groups.add(name);
            }
            groups.sort(String.CASE_INSENSITIVE_ORDER);
            return groups;
        } catch (IllegalStateException e) {
            if (e.getMessage() != null && (
                    e.getMessage().contains("returned HTML instead of JSON")
                            || e.getMessage().contains("returned invalid JSON")
                            || e.getMessage().contains("returned an empty response")
            )) {
                log.debug("Skipping assignment group fetch from ServiceNow: {}", e.getMessage());
                return List.of();
            }
            log.warn("Failed to fetch assignment groups from ServiceNow: {}", e.getMessage());
            return List.of();
        } catch (Exception e) {
            log.warn("Failed to fetch assignment groups from ServiceNow: {}", e.getMessage());
            return List.of();
        }
    }

    private HttpHeaders buildHeaders(ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        if (config.authType() == ServiceNowAuthType.BEARER) {
            headers.setBearerAuth(config.credentialSecret());
        } else {
            headers.setBasicAuth(
                    config.username() != null ? config.username() : "",
                    config.credentialSecret() != null ? config.credentialSecret() : "",
                    StandardCharsets.UTF_8
            );
        }
        return headers;
    }
}
