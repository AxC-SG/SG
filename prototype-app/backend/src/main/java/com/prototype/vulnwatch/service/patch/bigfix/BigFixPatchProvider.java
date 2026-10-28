package com.prototype.vulnwatch.service.patch.bigfix;

import com.prototype.vulnwatch.client.http.BigFixHostPolicy;
import com.prototype.vulnwatch.domain.FixAssetStatus;
import com.prototype.vulnwatch.domain.FixRecord;
import com.prototype.vulnwatch.domain.PatchConnectorConfig;
import com.prototype.vulnwatch.domain.PatchProviderType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.patch.PatchConnectionResult;
import com.prototype.vulnwatch.service.patch.PatchProvider;
import com.prototype.vulnwatch.service.patch.PatchSnapshot;
import java.net.URI;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

/**
 * HCL BigFix through its REST API and session relevance.
 *
 * <p>Every query is one of the fixed templates below; nothing from the tenant is spliced into
 * relevance. Patch content is limited to Fixlets in BigFix's patch sites ("Patches for …" and
 * "Enterprise Security"). Per-device state comes from Fixlet results (relevant = missing; became
 * non-relevant = installed) and from open actions' results (scheduled, running, pending restart,
 * failed).
 */
@Component
public class BigFixPatchProvider implements PatchProvider {

    static final int MAX_DEVICES = 200_000;
    static final int MAX_PATCHES = 50_000;
    static final int MAX_STATES = 1_000_000;
    static final int MAX_ACTIONS = 20_000;
    static final int MAX_ACTION_RESULTS = 1_000_000;

    private static final String PATCH_SITES = "(name of site of it as lowercase starts with \"patches for\""
            + " or name of site of it = \"Enterprise Security\")";
    static final String DEVICES = "(id of it as string, (name of it | \"\"), (operating system of it | \"\"))"
            + " of bes computers";
    static final String PATCHES = "(id of it as string, name of site of it, name of it, (source severity of it | \"\"),"
            + " (cve id list of it | \"\"), (source release date of it as string | \"\"), (category of it | \"\"))"
            + " of bes fixlets whose (fixlet flag of it and " + PATCH_SITES
            + " and exists results whose (relevant flag of it or exists last became nonrelevant of it) of it)";
    static final String STATES = "(id of fixlet of it as string, name of site of fixlet of it, id of computer of it as string,"
            + " relevant flag of it as string, (last became nonrelevant of it as string | \"\"))"
            + " of results whose (relevant flag of it or exists last became nonrelevant of it)"
            + " of bes fixlets whose (fixlet flag of it and " + PATCH_SITES + ")";
    static final String ACTIONS = "(id of it as string, (name of it | \"\"), state of it, (time issued of it as string | \"\"),"
            + " id of source fixlet of it as string, name of site of source fixlet of it)"
            + " of bes actions whose (exists source fixlet of it and state of it = \"Open\")";
    static final String ACTION_RESULTS = "(id of action of it as string, id of computer of it as string, status of it as string)"
            + " of results of bes actions whose (exists source fixlet of it and state of it = \"Open\")";

    private final BigFixApi api;
    private final BigFixHostPolicy hosts;

    public BigFixPatchProvider(BigFixApi api, BigFixHostPolicy hosts) {
        this.api = api;
        this.hosts = hosts;
    }

    @Override
    public PatchProviderType type() {
        return PatchProviderType.BIGFIX;
    }

    @Override
    public void validate(PatchConnectorConfig config, boolean secretPresent) {
        URI base = hosts.validateBaseUrl(config.getBaseUrl());
        hosts.resolveForConnection(base.getHost());
        config.setBaseUrl(base.toString());
        String username = config.getUsername();
        if (username == null || username.isBlank() || username.length() > 255 || username.contains(":")) {
            throw new IllegalArgumentException("A BigFix operator username is required (no colons)");
        }
        if (!secretPresent) throw new IllegalArgumentException("A BigFix operator password is required");
        config.setDirectoryId(null);
        config.setClientId(null);
    }

    @Override
    public PatchConnectionResult test(Tenant tenant, PatchConnectorConfig config, String secret) {
        URI base;
        try {
            base = hosts.validateBaseUrl(config.getBaseUrl());
            api.login(base, config.getUsername(), secret);
        } catch (RuntimeException failure) {
            return PatchConnectionResult.failed(failure.getMessage());
        }
        List<PatchConnectionResult.Check> checks = new ArrayList<>();
        checks.add(new PatchConnectionResult.Check("Operator sign-in", true, true, null));
        checks.add(count(base, config, secret, "Computers", "number of bes computers", true));
        checks.add(count(base, config, secret, "Patch Fixlets in patch sites",
                "number of bes fixlets whose (fixlet flag of it and " + PATCH_SITES + ")", true));
        checks.add(count(base, config, secret, "Open patch actions",
                "number of bes actions whose (exists source fixlet of it and state of it = \"Open\")", false));
        return PatchConnectionResult.of(checks, "BigFix patch data is reachable.");
    }

    private PatchConnectionResult.Check count(URI base, PatchConnectorConfig config, String secret, String name,
                                              String relevance, boolean required) {
        try {
            BigFixQueryParser.Rows rows = api.query(base, config.getUsername(), secret, relevance, 1);
            String value = rows.rows().isEmpty() ? "0" : rows.rows().get(0).get(0);
            boolean passed = !required || !"0".equals(value);
            return new PatchConnectionResult.Check(name, passed, required, value + " visible to this operator");
        } catch (RuntimeException failure) {
            return new PatchConnectionResult.Check(name, false, required, failure.getMessage());
        }
    }

    @Override
    public PatchSnapshot fetch(Tenant tenant, PatchConnectorConfig config, String secret) {
        URI base = hosts.validateBaseUrl(config.getBaseUrl());
        String user = config.getUsername();
        List<String> warnings = new ArrayList<>();
        BigFixQueryParser.Rows devices = api.query(base, user, secret, DEVICES, MAX_DEVICES);
        BigFixQueryParser.Rows patches = api.query(base, user, secret, PATCHES, MAX_PATCHES);
        BigFixQueryParser.Rows states = api.query(base, user, secret, STATES, MAX_STATES);
        boolean complete = !devices.truncated() && !patches.truncated() && !states.truncated();
        BigFixQueryParser.Rows actions = new BigFixQueryParser.Rows(List.of(), false);
        BigFixQueryParser.Rows actionResults = new BigFixQueryParser.Rows(List.of(), false);
        try {
            actions = api.query(base, user, secret, ACTIONS, MAX_ACTIONS);
            actionResults = api.query(base, user, secret, ACTION_RESULTS, MAX_ACTION_RESULTS);
            complete &= !actions.truncated() && !actionResults.truncated();
        } catch (RuntimeException optional) {
            warnings.add("BigFix actions could not be read: " + optional.getMessage());
            complete = false;
        }
        if (!complete) warnings.add("BigFix results exceeded import limits or were incomplete; this run is partial");
        return BigFixMapper.snapshot(devices.rows(), patches.rows(), states.rows(), actions.rows(), actionResults.rows(),
                complete, warnings);
    }

    /** Pure mapping from relevance rows to the provider-neutral snapshot; unit-tested on fixtures. */
    static final class BigFixMapper {

        private static final Pattern KB = Pattern.compile("\\bKB(\\d{6,8})\\b", Pattern.CASE_INSENSITIVE);
        private static final Pattern CVE = Pattern.compile("CVE-\\d{4}-\\d{4,}", Pattern.CASE_INSENSITIVE);
        private static final DateTimeFormatter DATE = DateTimeFormatter.ofPattern("d MMM yyyy", Locale.ENGLISH);
        /** "Wed, 15 Oct 2026 08:00:00 +0000" without the weekday, which is not validated. */
        private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("d MMM yyyy HH:mm:ss Z", Locale.ENGLISH);

        private BigFixMapper() { }

        static PatchSnapshot snapshot(List<List<String>> deviceRows, List<List<String>> patchRows, List<List<String>> stateRows,
                                      List<List<String>> actionRows, List<List<String>> actionResultRows,
                                      boolean complete, List<String> warnings) {
            List<PatchSnapshot.Device> devices = new ArrayList<>();
            for (List<String> row : deviceRows) {
                if (row.size() < 3 || blank(row.get(0))) continue;
                devices.add(new PatchSnapshot.Device(row.get(0), emptyToNull(row.get(1)), null, emptyToNull(row.get(2))));
            }

            List<PatchSnapshot.Patch> patches = new ArrayList<>();
            for (List<String> row : patchRows) {
                if (row.size() < 7 || blank(row.get(0))) continue;
                String site = row.get(1);
                String name = row.get(2);
                Matcher kb = KB.matcher(name == null ? "" : name);
                patches.add(new PatchSnapshot.Patch(
                        externalId(site, row.get(0)),
                        kb.find() ? kb.group(1) : null,
                        null,
                        name,
                        vendor(site),
                        site,
                        emptyToNull(row.get(6)),
                        emptyToNull(row.get(3)),
                        severity(row.get(3)),
                        ecosystem(site),
                        date(row.get(5)),
                        name != null && name.toLowerCase(Locale.ROOT).contains("(superseded)"),
                        null,
                        cves(row.get(4))));
            }

            Map<String, PatchSnapshot.Status> statuses = new HashMap<>();
            for (List<String> row : stateRows) {
                if (row.size() < 5) continue;
                String patchId = externalId(row.get(1), row.get(0));
                String device = row.get(2);
                boolean relevant = "true".equalsIgnoreCase(row.get(3));
                FixAssetStatus status = relevant ? FixAssetStatus.MISSING : FixAssetStatus.INSTALLED;
                Instant installedAt = relevant ? null : time(row.get(4));
                statuses.put(device + "|" + patchId,
                        new PatchSnapshot.Status(device, patchId, status, null, null, null, installedAt, null));
            }

            Map<String, String> actionFixlet = new HashMap<>();
            List<PatchSnapshot.Deployment> deployments = new ArrayList<>();
            for (List<String> row : actionRows) {
                if (row.size() < 6 || blank(row.get(0))) continue;
                actionFixlet.put(row.get(0), externalId(row.get(5), row.get(4)));
                deployments.add(new PatchSnapshot.Deployment(row.get(0), emptyToNull(row.get(1)), row.get(2), null,
                        time(row.get(3)), null));
            }
            for (List<String> row : actionResultRows) {
                if (row.size() < 3) continue;
                String patchId = actionFixlet.get(row.get(0));
                FixAssetStatus status = actionStatus(row.get(2));
                if (patchId == null || status == null) continue;
                String key = row.get(1) + "|" + patchId;
                PatchSnapshot.Status current = statuses.get(key);
                // A non-relevant result is the ground truth for "installed"; actions refine a missing patch.
                if (current != null && current.status() == FixAssetStatus.INSTALLED) continue;
                statuses.put(key, new PatchSnapshot.Status(row.get(1), patchId, status, row.get(0), null, null,
                        null, status == FixAssetStatus.FAILED ? limit(row.get(2), 64) : null));
            }
            return new PatchSnapshot(devices, patches, deployments, new ArrayList<>(statuses.values()), complete, warnings);
        }

        /** Fixlet IDs are unique only within a site. */
        static String externalId(String site, String fixletId) {
            String id = (site == null ? "" : site) + "/" + fixletId;
            return id.length() <= 255 ? id : id.substring(0, 255);
        }

        static FixAssetStatus actionStatus(String status) {
            String value = status == null ? "" : status.toLowerCase(Locale.ROOT);
            if (value.equals("fixed")) return FixAssetStatus.INSTALLED;
            if (value.contains("pending restart")) return FixAssetStatus.PENDING_REBOOT;
            if (value.contains("failed") || value.equals("error")) return FixAssetStatus.FAILED;
            if (value.equals("running") || value.equals("evaluating") || value.contains("downloading")) return FixAssetStatus.IN_PROGRESS;
            if (value.contains("waiting") || value.contains("pending") || value.contains("constrained")) return FixAssetStatus.SCHEDULED;
            return null;
        }

        static String severity(String value) {
            return switch (value == null ? "" : value.trim().toLowerCase(Locale.ROOT)) {
                case "critical" -> "CRITICAL";
                case "important", "high" -> "HIGH";
                case "moderate", "medium" -> "MEDIUM";
                case "low" -> "LOW";
                default -> null;
            };
        }

        static FixRecord.Ecosystem ecosystem(String site) {
            String value = site == null ? "" : site.toLowerCase(Locale.ROOT);
            if (value.equals("enterprise security") || value.contains("windows")) return FixRecord.Ecosystem.WINDOWS;
            if (value.contains("mac")) return FixRecord.Ecosystem.MACOS;
            for (String linux : List.of("rhel", "red hat", "suse", "sles", "ubuntu", "debian", "centos", "oracle linux",
                    "amazon linux", "rocky", "alma", "linux")) {
                if (value.contains(linux)) return FixRecord.Ecosystem.LINUX;
            }
            return FixRecord.Ecosystem.CROSS_PLATFORM;
        }

        static List<String> cves(String list) {
            Set<String> result = new LinkedHashSet<>();
            Matcher matcher = CVE.matcher(list == null ? "" : list);
            while (matcher.find() && result.size() < 500) result.add(matcher.group().toUpperCase(Locale.ROOT));
            return List.copyOf(result);
        }

        static Instant time(String value) {
            if (blank(value)) return null;
            try {
                String trimmed = value.trim();
                int comma = trimmed.indexOf(',');
                return ZonedDateTime.parse(comma >= 0 ? trimmed.substring(comma + 1).trim() : trimmed, TIME).toInstant();
            } catch (Exception unparseable) {
                return null;
            }
        }

        static Instant date(String value) {
            if (blank(value)) return null;
            try {
                // "Tue, 14 Oct 2026": the weekday name is informational, so it is not validated.
                String trimmed = value.trim();
                int comma = trimmed.indexOf(',');
                return LocalDate.parse(comma >= 0 ? trimmed.substring(comma + 1).trim() : trimmed, DATE)
                        .atStartOfDay(ZoneOffset.UTC).toInstant();
            } catch (Exception unparseable) {
                return time(value);
            }
        }

        private static String vendor(String site) {
            FixRecord.Ecosystem ecosystem = ecosystem(site);
            return ecosystem == FixRecord.Ecosystem.WINDOWS ? "Microsoft" : null;
        }

        private static boolean blank(String value) {
            return value == null || value.isBlank();
        }

        private static String emptyToNull(String value) {
            return blank(value) ? null : value.trim();
        }

        private static String limit(String value, int max) {
            return value == null || value.length() <= max ? value : value.substring(0, max);
        }
    }
}
