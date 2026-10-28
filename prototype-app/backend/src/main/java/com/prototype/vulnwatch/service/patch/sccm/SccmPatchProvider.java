package com.prototype.vulnwatch.service.patch.sccm;

import com.prototype.vulnwatch.domain.FixAssetStatus;
import com.prototype.vulnwatch.domain.FixRecord;
import com.prototype.vulnwatch.domain.PatchConnectorConfig;
import com.prototype.vulnwatch.domain.PatchProviderType;
import com.prototype.vulnwatch.domain.SccmCmdbConfig;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.SccmCmdbConfigRepository;
import com.prototype.vulnwatch.service.SccmQueryService;
import com.prototype.vulnwatch.service.patch.PatchConnectionResult;
import com.prototype.vulnwatch.service.patch.PatchProvider;
import com.prototype.vulnwatch.service.patch.PatchSnapshot;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * SCCM/MECM patches, read over the tenant's existing SCCM SQL connection (and so the same
 * host allowlist, SQL authentication and URL checks as SCCM inventory). Only fixed SQL runs.
 *
 * <p>SCCM update metadata carries no CVE list, so CVEs come from the KB article through
 * Microsoft CSAF in {@code PatchIngestionService}.
 */
@Component
public class SccmPatchProvider implements PatchProvider {

    static final int MAX_DEVICES = 200_000;
    static final int MAX_UPDATES = 50_000;
    static final int MAX_STATES = 500_000;
    static final int MAX_ASSIGNMENTS = 100_000;

    static final String DEVICES_SQL = """
            SELECT CAST(ResourceID AS VARCHAR(50)) AS resource_id, Name0 AS name,
                   Operating_System_Name_and0 AS os_name
              FROM v_R_System
             WHERE Active0 = 1 AND Obsolete0 = 0
            """;

    /** Security updates only: SCCM gives every security update a severity above zero. */
    static final String UPDATES_SQL = """
            SELECT CAST(CI_ID AS VARCHAR(50)) AS ci_id, ArticleID AS article_id, BulletinID AS bulletin_id,
                   Title AS title, CAST(Severity AS VARCHAR(10)) AS severity,
                   CONVERT(VARCHAR(33), DatePosted, 126) AS date_posted,
                   CAST(IsSuperseded AS VARCHAR(5)) AS is_superseded, InfoURL AS info_url
              FROM v_UpdateInfo
             WHERE IsExpired = 0 AND Severity > 0
            """;

    /** 2 = required (missing), 3 = installed; not-required and unknown rows are not imported. */
    static final String STATES_SQL = """
            SELECT CAST(ucs.ResourceID AS VARCHAR(50)) AS resource_id, CAST(ucs.CI_ID AS VARCHAR(50)) AS ci_id,
                   CAST(ucs.Status AS VARCHAR(5)) AS status
              FROM v_UpdateComplianceStatus ucs
              JOIN v_UpdateInfo ui ON ui.CI_ID = ucs.CI_ID
             WHERE ui.IsExpired = 0 AND ui.Severity > 0 AND ucs.Status IN (2, 3)
            """;

    static final String ASSIGNMENTS_SQL = """
            SELECT CAST(a.AssignmentID AS VARCHAR(50)) AS assignment_id, a.AssignmentName AS name,
                   a.CollectionName AS collection, CONVERT(VARCHAR(33), a.StartTime, 126) AS start_time,
                   CONVERT(VARCHAR(33), a.EnforcementDeadline, 126) AS deadline,
                   CAST(atc.CI_ID AS VARCHAR(50)) AS ci_id
              FROM v_CIAssignment a
              JOIN v_CIAssignmentToCI atc ON atc.AssignmentID = a.AssignmentID
              JOIN v_UpdateInfo ui ON ui.CI_ID = atc.CI_ID
             WHERE ui.IsExpired = 0 AND ui.Severity > 0
            """;

    private final SccmCmdbConfigRepository sccmConfigs;
    private final SccmQueryService queries;

    public SccmPatchProvider(SccmCmdbConfigRepository sccmConfigs, SccmQueryService queries) {
        this.sccmConfigs = sccmConfigs;
        this.queries = queries;
    }

    @Override
    public PatchProviderType type() {
        return PatchProviderType.SCCM;
    }

    /** Uses the SCCM inventory connector's connection; there is no second SCCM secret. */
    @Override
    public boolean requiresSecret() {
        return false;
    }

    @Override
    public void validate(PatchConnectorConfig config, boolean secretPresent) {
        if (sccmConnection(config.getTenant()).isEmpty()) {
            throw new IllegalArgumentException(
                    "Configure the SCCM/MECM inventory connector first; patch sync uses its SQL connection");
        }
    }

    @Override
    public PatchConnectionResult test(Tenant tenant, PatchConnectorConfig config, String secret) {
        Optional<SccmCmdbConfig> sccm = sccmConnection(tenant);
        if (sccm.isEmpty()) {
            return PatchConnectionResult.failed("The SCCM/MECM inventory connector is not configured");
        }
        List<PatchConnectionResult.Check> checks = new ArrayList<>();
        checks.add(probe(sccm.get(), "Update catalog (v_UpdateInfo)", "SELECT TOP 1 CI_ID FROM v_UpdateInfo", true));
        checks.add(probe(sccm.get(), "Device compliance (v_UpdateComplianceStatus)",
                "SELECT TOP 1 ResourceID FROM v_UpdateComplianceStatus", true));
        checks.add(probe(sccm.get(), "Deployments and schedules (v_CIAssignment)",
                "SELECT TOP 1 AssignmentID FROM v_CIAssignment", false));
        return PatchConnectionResult.of(checks, "SCCM patch data is reachable.");
    }

    private PatchConnectionResult.Check probe(SccmCmdbConfig config, String name, String sql, boolean required) {
        try {
            queries.queryRows(config, sql, 1);
            return new PatchConnectionResult.Check(name, true, required, null);
        } catch (Exception failure) {
            return new PatchConnectionResult.Check(name, false, required, failure.getMessage());
        }
    }

    @Override
    public PatchSnapshot fetch(Tenant tenant, PatchConnectorConfig config, String secret) {
        SccmCmdbConfig sccm = sccmConnection(tenant)
                .orElseThrow(() -> new IllegalStateException("The SCCM/MECM inventory connector is not configured"));
        List<String> warnings = new ArrayList<>();
        boolean complete = true;
        try {
            SccmQueryService.QueryRows deviceRows = queries.queryRows(sccm, DEVICES_SQL, MAX_DEVICES);
            SccmQueryService.QueryRows updateRows = queries.queryRows(sccm, UPDATES_SQL, MAX_UPDATES);
            SccmQueryService.QueryRows stateRows = queries.queryRows(sccm, STATES_SQL, MAX_STATES);
            complete = !deviceRows.truncated() && !updateRows.truncated() && !stateRows.truncated();
            if (!complete) warnings.add("SCCM results exceeded import limits; this run is partial");

            Map<String, Schedule> schedules = new HashMap<>();
            List<PatchSnapshot.Deployment> deployments = new ArrayList<>();
            try {
                SccmQueryService.QueryRows assignmentRows = queries.queryRows(sccm, ASSIGNMENTS_SQL, MAX_ASSIGNMENTS);
                mapAssignments(assignmentRows.rows(), deployments, schedules);
            } catch (Exception optional) {
                warnings.add("SCCM deployment schedules could not be read: " + optional.getMessage());
            }
            return SccmPatchMapper.snapshot(deviceRows.rows(), updateRows.rows(), stateRows.rows(), deployments,
                    schedules, Instant.now(), complete, warnings);
        } catch (Exception failure) {
            throw new IllegalStateException("SCCM patch query failed: " + failure.getMessage(), failure);
        }
    }

    private static void mapAssignments(List<Map<String, String>> rows, List<PatchSnapshot.Deployment> deployments,
                                       Map<String, Schedule> schedules) {
        Map<String, PatchSnapshot.Deployment> byId = new HashMap<>();
        for (Map<String, String> row : rows) {
            String id = row.get("assignment_id");
            if (id == null) continue;
            Instant start = parseTime(row.get("start_time"));
            Instant deadline = parseTime(row.get("deadline"));
            byId.computeIfAbsent(id, key -> new PatchSnapshot.Deployment(key, row.get("name"), null,
                    row.get("collection"), start, deadline));
            String ci = row.get("ci_id");
            if (ci != null) {
                Schedule current = schedules.get(ci);
                // The earliest deployment that has not passed its deadline is the one that matters.
                if (current == null || (start != null && (current.startsAt() == null || start.isBefore(current.startsAt())))) {
                    schedules.put(ci, new Schedule(id, start, deadline));
                }
            }
        }
        deployments.addAll(byId.values());
    }

    private Optional<SccmCmdbConfig> sccmConnection(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) return Optional.empty();
        return sccmConfigs.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "sccm")
                .filter(config -> config.getJdbcUrl() != null && !config.getJdbcUrl().isBlank());
    }

    static Instant parseTime(String value) {
        if (value == null || value.isBlank()) return null;
        try {
            // SQL Server returns "yyyy-MM-dd HH:mm:ss.fff" through getString.
            String iso = value.trim().replace(' ', 'T');
            return LocalDateTime.parse(iso.length() > 19 ? iso.substring(0, 19) : iso).toInstant(ZoneOffset.UTC);
        } catch (Exception unparseable) {
            return null;
        }
    }

    record Schedule(String deploymentId, Instant startsAt, Instant deadlineAt) {}

    /** Pure mapping from SCCM rows to the provider-neutral snapshot; unit-tested on fixtures. */
    static final class SccmPatchMapper {

        private SccmPatchMapper() { }

        static PatchSnapshot snapshot(List<Map<String, String>> deviceRows, List<Map<String, String>> updateRows,
                                      List<Map<String, String>> stateRows, List<PatchSnapshot.Deployment> deployments,
                                      Map<String, Schedule> schedules, Instant now, boolean complete, List<String> warnings) {
            List<PatchSnapshot.Device> devices = new ArrayList<>();
            for (Map<String, String> row : deviceRows) {
                if (row.get("resource_id") == null) continue;
                devices.add(new PatchSnapshot.Device(row.get("resource_id"), row.get("name"), null, row.get("os_name")));
            }
            List<PatchSnapshot.Patch> patches = new ArrayList<>();
            for (Map<String, String> row : updateRows) {
                if (row.get("ci_id") == null) continue;
                String severityCode = row.get("severity");
                patches.add(new PatchSnapshot.Patch(
                        row.get("ci_id"),
                        row.get("article_id"),
                        row.get("bulletin_id"),
                        row.get("title"),
                        "Microsoft",
                        null,
                        "Security Updates",
                        vendorSeverity(severityCode),
                        severity(severityCode),
                        FixRecord.Ecosystem.WINDOWS,
                        parseTime(row.get("date_posted")),
                        "1".equals(row.get("is_superseded")) || "true".equalsIgnoreCase(row.get("is_superseded")),
                        row.get("info_url"),
                        List.of()));
            }
            List<PatchSnapshot.Status> statuses = new ArrayList<>();
            for (Map<String, String> row : stateRows) {
                String ci = row.get("ci_id");
                String device = row.get("resource_id");
                if (ci == null || device == null) continue;
                Schedule schedule = schedules.get(ci);
                if ("3".equals(row.get("status"))) {
                    statuses.add(new PatchSnapshot.Status(device, ci, FixAssetStatus.INSTALLED, null, null, null, null, null));
                } else if ("2".equals(row.get("status"))) {
                    statuses.add(required(device, ci, schedule, now));
                }
            }
            return new PatchSnapshot(devices, patches, deployments, statuses, complete, warnings);
        }

        /** A required update is scheduled, in its deployment window, or missing (including overdue). */
        static PatchSnapshot.Status required(String device, String ci, Schedule schedule, Instant now) {
            if (schedule == null) {
                return new PatchSnapshot.Status(device, ci, FixAssetStatus.MISSING, null, null, null, null, null);
            }
            FixAssetStatus status;
            if (schedule.startsAt() != null && schedule.startsAt().isAfter(now)) {
                status = FixAssetStatus.SCHEDULED;
            } else if (schedule.deadlineAt() == null || schedule.deadlineAt().isAfter(now)) {
                status = FixAssetStatus.IN_PROGRESS;
            } else {
                status = FixAssetStatus.MISSING;
            }
            return new PatchSnapshot.Status(device, ci, status, schedule.deploymentId(), schedule.startsAt(),
                    schedule.deadlineAt(), null, null);
        }

        static String severity(String code) {
            return switch (code == null ? "" : code) {
                case "10" -> "CRITICAL";
                case "8" -> "HIGH";
                case "6" -> "MEDIUM";
                case "2" -> "LOW";
                default -> null;
            };
        }

        static String vendorSeverity(String code) {
            return switch (code == null ? "" : code) {
                case "10" -> "Critical";
                case "8" -> "Important";
                case "6" -> "Moderate";
                case "2" -> "Low";
                default -> null;
            };
        }
    }
}
