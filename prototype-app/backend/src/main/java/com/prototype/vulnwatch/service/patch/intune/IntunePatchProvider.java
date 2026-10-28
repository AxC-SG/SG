package com.prototype.vulnwatch.service.patch.intune;

import com.fasterxml.jackson.databind.JsonNode;
import com.prototype.vulnwatch.domain.FixAssetStatus;
import com.prototype.vulnwatch.domain.FixRecord;
import com.prototype.vulnwatch.domain.PatchConnectorConfig;
import com.prototype.vulnwatch.domain.PatchProviderType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.patch.PatchConnectionResult;
import com.prototype.vulnwatch.service.patch.PatchProvider;
import com.prototype.vulnwatch.service.patch.PatchSnapshot;
import com.prototype.vulnwatch.service.patch.intune.IntuneGraphClient.Listing;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

/**
 * Microsoft Intune through Microsoft Graph.
 *
 * <ul>
 *   <li>Devices: {@code v1.0/deviceManagement/managedDevices}.</li>
 *   <li>Patches: Windows quality updates from the Windows Update for Business deployment service
 *       catalog ({@code beta/admin/windows/updates/catalog/entries}), with KB and CVE severity.</li>
 *   <li>Deployment state: that service's deployments and their audience members. Graph does not
 *       expose per-device install results, so Intune reports SCHEDULED / IN_PROGRESS / FAILED for
 *       devices in a deployment and never claims an update is installed.</li>
 * </ul>
 * The catalog and deployment calls are beta APIs that need {@code WindowsUpdates.ReadWrite.All};
 * only GET requests are made. Without them, devices still import and the run is marked partial.
 */
@Component
public class IntunePatchProvider implements PatchProvider {

    static final int MAX_PAGES = 500;
    static final int MAX_DEVICES = 200_000;
    static final int MAX_CATALOG = 20_000;
    static final int MAX_DEPLOYMENTS = 2_000;
    static final int MAX_MEMBERS = 200_000;
    /** Security updates older than this are left out unless a deployment still targets them. */
    static final int CATALOG_WINDOW_DAYS = 400;

    static final String DEVICES = "v1.0/deviceManagement/managedDevices"
            + "?$select=id,deviceName,serialNumber,operatingSystem,osVersion,azureADDeviceId&$top=999";
    static final String CATALOG = "beta/admin/windows/updates/catalog/entries"
            + "?$filter=isof('microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry')"
            + "&$expand=microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry/productRevisions";
    static final String DEPLOYMENTS = "beta/admin/windows/updates/deployments";
    private static final Pattern SAFE_ID = Pattern.compile("^[A-Za-z0-9_.:-]{1,128}$");

    private final IntuneGraphClient graph;

    public IntunePatchProvider(IntuneGraphClient graph) {
        this.graph = graph;
    }

    @Override
    public PatchProviderType type() {
        return PatchProviderType.INTUNE;
    }

    @Override
    public void validate(PatchConnectorConfig config, boolean secretPresent) {
        if (!guid(config.getDirectoryId())) throw new IllegalArgumentException("Directory (tenant) ID must be a GUID");
        if (!guid(config.getClientId())) throw new IllegalArgumentException("Application (client) ID must be a GUID");
        if (!secretPresent) throw new IllegalArgumentException("A client secret is required");
        // Intune uses fixed Microsoft hosts; nothing else about the connection is configurable.
        config.setBaseUrl(null);
        config.setUsername(null);
    }

    @Override
    public PatchConnectionResult test(Tenant tenant, PatchConnectorConfig config, String secret) {
        String token;
        try {
            token = graph.token(config.getDirectoryId(), config.getClientId(), secret);
        } catch (RuntimeException failure) {
            return PatchConnectionResult.failed(failure.getMessage());
        }
        List<PatchConnectionResult.Check> checks = new ArrayList<>();
        checks.add(new PatchConnectionResult.Check("Entra ID sign-in", true, true, null));
        checks.add(probe(token, "Managed devices (DeviceManagementManagedDevices.Read.All)",
                "v1.0/deviceManagement/managedDevices?$select=id&$top=1", true));
        checks.add(probe(token, "Windows update catalog (WindowsUpdates.ReadWrite.All)",
                "beta/admin/windows/updates/catalog/entries?$top=1", false));
        checks.add(probe(token, "Update deployments (WindowsUpdates.ReadWrite.All)", DEPLOYMENTS + "?$top=1", false));
        return PatchConnectionResult.of(checks, "Intune data is reachable through Microsoft Graph.");
    }

    private PatchConnectionResult.Check probe(String token, String name, String path, boolean required) {
        try {
            graph.first(token, path);
            return new PatchConnectionResult.Check(name, true, required, null);
        } catch (RuntimeException failure) {
            return new PatchConnectionResult.Check(name, false, required, failure.getMessage());
        }
    }

    @Override
    public PatchSnapshot fetch(Tenant tenant, PatchConnectorConfig config, String secret) {
        String token = graph.token(config.getDirectoryId(), config.getClientId(), secret);
        List<String> warnings = new ArrayList<>();
        Listing devices = graph.list(token, DEVICES, MAX_PAGES, MAX_DEVICES);
        boolean complete = devices.complete();
        if (devices.warning() != null) warnings.add(devices.warning());

        Listing catalog = optional(() -> graph.list(token, CATALOG, MAX_PAGES, MAX_CATALOG), "Windows update catalog", warnings);
        Listing deployments = optional(() -> graph.list(token, DEPLOYMENTS, MAX_PAGES, MAX_DEPLOYMENTS), "Update deployments", warnings);
        complete &= catalog.complete() && deployments.complete();

        Map<String, List<JsonNode>> membersByDeployment = new HashMap<>();
        int members = 0;
        for (JsonNode deployment : deployments.items()) {
            String id = deployment.path("id").asText("");
            if (!SAFE_ID.matcher(id).matches() || IntuneMapper.isArchived(deployment)) continue;
            if (members >= MAX_MEMBERS) {
                warnings.add("Deployment audiences exceeded the import limit");
                complete = false;
                break;
            }
            Listing audience = optional(() -> graph.list(token, DEPLOYMENTS + "/" + id + "/audience/members",
                    MAX_PAGES, MAX_MEMBERS), "Audience of deployment " + id, warnings);
            complete &= audience.complete();
            members += audience.items().size();
            membersByDeployment.put(id, audience.items());
        }
        return IntuneMapper.snapshot(devices.items(), catalog.items(), deployments.items(), membersByDeployment,
                Instant.now(), complete, warnings);
    }

    private static Listing optional(java.util.function.Supplier<Listing> call, String name, List<String> warnings) {
        try {
            Listing listing = call.get();
            if (listing.warning() != null) warnings.add(listing.warning());
            return listing;
        } catch (RuntimeException failure) {
            warnings.add(name + " could not be read: " + failure.getMessage());
            return new Listing(List.of(), false, null);
        }
    }

    private static boolean guid(String value) {
        return value != null && IntuneGraphClient.GUID.matcher(value.trim()).matches();
    }

    /** Pure mapping from Graph JSON to the provider-neutral snapshot; unit-tested on fixtures. */
    static final class IntuneMapper {

        private IntuneMapper() { }

        static PatchSnapshot snapshot(List<JsonNode> deviceItems, List<JsonNode> catalogItems, List<JsonNode> deploymentItems,
                                      Map<String, List<JsonNode>> membersByDeployment, Instant now, boolean complete,
                                      List<String> warnings) {
            List<PatchSnapshot.Device> devices = new ArrayList<>();
            Map<String, String> managedIdByEntraId = new HashMap<>();
            for (JsonNode device : deviceItems) {
                String id = text(device, "id");
                if (id == null) continue;
                devices.add(new PatchSnapshot.Device(id, text(device, "deviceName"), text(device, "serialNumber"),
                        join(text(device, "operatingSystem"), text(device, "osVersion"))));
                String entraId = text(device, "azureADDeviceId");
                if (entraId != null && !"00000000-0000-0000-0000-000000000000".equals(entraId)) {
                    managedIdByEntraId.put(entraId.toLowerCase(Locale.ROOT), id);
                }
            }

            // The catalog is global: keep what a deployment targets plus recent security updates.
            java.util.Set<String> deployed = new java.util.HashSet<>();
            for (JsonNode deployment : deploymentItems) {
                String catalogId = text(deployment.path("content").path("catalogEntry"), "id");
                if (catalogId != null && !isArchived(deployment)) deployed.add(catalogId);
            }
            Instant recent = now.minus(java.time.Duration.ofDays(CATALOG_WINDOW_DAYS));
            List<PatchSnapshot.Patch> patches = new ArrayList<>();
            for (JsonNode entry : catalogItems) {
                String id = text(entry, "id");
                if (id == null) continue;
                Instant released = time(text(entry, "releaseDateTime"));
                boolean recentSecurity = "security".equalsIgnoreCase(text(entry, "qualityUpdateClassification"))
                        && released != null && released.isAfter(recent);
                if (!deployed.contains(id) && !recentSecurity) continue;
                JsonNode cveInfo = entry.path("cveSeverityInformation");
                String vendorSeverity = text(cveInfo, "maxSeverity");
                List<String> cves = new ArrayList<>();
                cveInfo.path("exploitedCves").forEach(cve -> {
                    String number = text(cve, "number");
                    if (number != null) cves.add(number.toUpperCase(Locale.ROOT));
                });
                JsonNode kb = entry.path("productRevisions").path(0).path("knowledgeBaseArticle");
                patches.add(new PatchSnapshot.Patch(
                        id,
                        text(kb, "id"),
                        null,
                        text(entry, "displayName"),
                        "Microsoft",
                        "Windows",
                        text(entry, "qualityUpdateClassification"),
                        vendorSeverity,
                        severity(vendorSeverity),
                        FixRecord.Ecosystem.WINDOWS,
                        released,
                        false,
                        text(kb, "url"),
                        cves));
            }

            List<PatchSnapshot.Deployment> deployments = new ArrayList<>();
            List<PatchSnapshot.Status> statuses = new ArrayList<>();
            for (JsonNode deployment : deploymentItems) {
                String id = text(deployment, "id");
                String catalogId = text(deployment.path("content").path("catalogEntry"), "id");
                if (id == null || catalogId == null || isArchived(deployment)) continue;
                String state = text(deployment.path("state"), "effectiveValue");
                Instant startsAt = time(text(deployment.path("settings").path("schedule"), "startDateTime"));
                deployments.add(new PatchSnapshot.Deployment(id, "Windows Update deployment " + id, state, null, startsAt, null));
                FixAssetStatus status = deviceStatus(state, startsAt, now);
                for (JsonNode member : membersByDeployment.getOrDefault(id, List.of())) {
                    String entraId = text(member, "id");
                    String managedId = entraId == null ? null : managedIdByEntraId.get(entraId.toLowerCase(Locale.ROOT));
                    if (managedId == null) continue;
                    statuses.add(new PatchSnapshot.Status(managedId, catalogId, status, id,
                            status == FixAssetStatus.SCHEDULED ? startsAt : null, null, null, null));
                }
            }
            return new PatchSnapshot(devices, patches, deployments, statuses, complete, warnings);
        }

        static boolean isArchived(JsonNode deployment) {
            return "archived".equalsIgnoreCase(text(deployment.path("state"), "effectiveValue"));
        }

        /** Deployment service states for a device in the audience; installation is never inferred. */
        static FixAssetStatus deviceStatus(String state, Instant startsAt, Instant now) {
            String value = state == null ? "" : state.toLowerCase(Locale.ROOT);
            if ("faulted".equals(value)) return FixAssetStatus.FAILED;
            if ("scheduled".equals(value) || (startsAt != null && startsAt.isAfter(now))) return FixAssetStatus.SCHEDULED;
            if ("offering".equals(value)) return FixAssetStatus.IN_PROGRESS;
            return FixAssetStatus.MISSING;
        }

        static String severity(String maxSeverity) {
            return switch (maxSeverity == null ? "" : maxSeverity.toLowerCase(Locale.ROOT)) {
                case "critical" -> "CRITICAL";
                case "important" -> "HIGH";
                case "moderate" -> "MEDIUM";
                case "low" -> "LOW";
                default -> null;
            };
        }

        static Instant time(String value) {
            if (value == null) return null;
            try {
                return OffsetDateTime.parse(value).toInstant();
            } catch (Exception unparseable) {
                return null;
            }
        }

        private static String text(JsonNode node, String field) {
            JsonNode value = node.path(field);
            if (value.isMissingNode() || value.isNull()) return null;
            String text = value.asText();
            return text.isBlank() ? null : text;
        }

        private static String join(String os, String version) {
            if (os == null) return version;
            return version == null ? os : os + " " + version;
        }
    }
}
