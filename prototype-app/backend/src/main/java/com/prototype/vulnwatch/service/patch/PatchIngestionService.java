package com.prototype.vulnwatch.service.patch;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.Ci;
import com.prototype.vulnwatch.domain.DeviceIdentity;
import com.prototype.vulnwatch.domain.FixAsset;
import com.prototype.vulnwatch.domain.FixAssetEvent;
import com.prototype.vulnwatch.domain.FixAssetStatus;
import com.prototype.vulnwatch.domain.FixPatchDetail;
import com.prototype.vulnwatch.domain.FixRecord;
import com.prototype.vulnwatch.domain.FixRecordCve;
import com.prototype.vulnwatch.domain.PatchDeployment;
import com.prototype.vulnwatch.domain.PatchProviderType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.CiRepository;
import com.prototype.vulnwatch.repo.DeviceIdentityRepository;
import com.prototype.vulnwatch.repo.FixAssetEventRepository;
import com.prototype.vulnwatch.repo.FixAssetRepository;
import com.prototype.vulnwatch.repo.FixPatchDetailRepository;
import com.prototype.vulnwatch.repo.FixRecordCveRepository;
import com.prototype.vulnwatch.repo.FixRecordRepository;
import com.prototype.vulnwatch.repo.PatchDeploymentRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Turns one provider's {@link PatchSnapshot} into Fix Intelligence records for one tenant.
 *
 * <p>Runs inside the tenant's schema and transaction (the sync service establishes the tenant
 * context first), so every read and write is tenant-scoped by schema and forced RLS. Devices are
 * matched only to that tenant's assets: by the tool's own device id, then serial number, then
 * short hostname. An unmatched device becomes a new host; an ambiguous one (several hosts share
 * the name) is skipped with a warning rather than guessed.
 *
 * <p>Patches are deduplicated per tenant: one PATCH fix per Microsoft KB no matter how many tools
 * report it, with one {@link FixPatchDetail} per tool. Fix records only ever describe patch state;
 * they never change finding status.
 */
@Service
public class PatchIngestionService {

    private static final Pattern CVE = Pattern.compile("^CVE-\\d{4}-\\d{4,}$");
    private static final Map<String, Integer> SEVERITY_RANK = Map.of("NONE", 0, "LOW", 1, "MEDIUM", 2, "HIGH", 3, "CRITICAL", 4);

    private final AssetRepository assets;
    private final CiRepository cis;
    private final DeviceIdentityRepository devices;
    private final FixRecordRepository fixes;
    private final FixRecordCveRepository fixCves;
    private final FixPatchDetailRepository patchDetails;
    private final PatchDeploymentRepository deployments;
    private final FixAssetRepository fixAssets;
    private final FixAssetEventRepository events;
    private final KbCveResolver kbCveResolver;

    public PatchIngestionService(
            AssetRepository assets,
            CiRepository cis,
            DeviceIdentityRepository devices,
            FixRecordRepository fixes,
            FixRecordCveRepository fixCves,
            FixPatchDetailRepository patchDetails,
            PatchDeploymentRepository deployments,
            FixAssetRepository fixAssets,
            FixAssetEventRepository events,
            KbCveResolver kbCveResolver
    ) {
        this.assets = assets;
        this.cis = cis;
        this.devices = devices;
        this.fixes = fixes;
        this.fixCves = fixCves;
        this.patchDetails = patchDetails;
        this.deployments = deployments;
        this.fixAssets = fixAssets;
        this.events = events;
        this.kbCveResolver = kbCveResolver;
    }

    public record Result(
            int devicesMatched,
            int hostsCreated,
            int devicesSkipped,
            int patchesUpserted,
            int cveLinks,
            int deploymentsUpserted,
            int statusesUpserted,
            int statusChanges,
            List<String> warnings
    ) {}

    @Transactional
    public Result ingest(Tenant tenant, PatchProviderType provider, PatchSnapshot snapshot) {
        Instant now = Instant.now();
        List<String> warnings = new ArrayList<>(snapshot.warnings());
        Counters counters = new Counters();

        Map<String, UUID> assetByDevice = new HashMap<>();
        for (PatchSnapshot.Device device : snapshot.devices()) {
            if (blank(device.externalId())) continue;
            Optional<UUID> asset = resolveDevice(tenant, provider, device, now, counters);
            if (asset.isPresent()) {
                assetByDevice.put(device.externalId(), asset.get());
            } else {
                counters.skipped++;
                warnings.add("Device " + safe(device.hostname()) + " matches more than one host; its patch state was skipped");
            }
        }

        KbCveResolver.Lookup kbLookup = kbCveResolver.newLookup();
        Map<String, UUID> fixByPatch = new HashMap<>();
        for (PatchSnapshot.Patch patch : snapshot.patches()) {
            if (blank(patch.externalId())) continue;
            fixByPatch.put(patch.externalId(), upsertPatch(tenant, provider, patch, now, kbLookup, counters));
        }

        Map<String, UUID> deploymentIds = new HashMap<>();
        for (PatchSnapshot.Deployment deployment : snapshot.deployments()) {
            if (blank(deployment.externalId())) continue;
            deploymentIds.put(deployment.externalId(), upsertDeployment(tenant, provider, deployment, now));
            counters.deployments++;
        }

        for (PatchSnapshot.Status status : snapshot.statuses()) {
            UUID assetId = assetByDevice.get(status.deviceExternalId());
            UUID fixId = fixByPatch.get(status.patchExternalId());
            if (assetId == null || fixId == null || status.status() == null) continue;
            upsertStatus(tenant, provider, fixId, assetId, status,
                    status.deploymentExternalId() == null ? null : deploymentIds.get(status.deploymentExternalId()),
                    now, counters);
        }
        return new Result(counters.matched, counters.created, counters.skipped, counters.patches, counters.cveLinks,
                counters.deployments, counters.statuses, counters.changes, List.copyOf(warnings));
    }

    // ── Devices ──────────────────────────────────────────────────────────────────────────────

    private Optional<UUID> resolveDevice(Tenant tenant, PatchProviderType provider, PatchSnapshot.Device device,
                                         Instant now, Counters counters) {
        String shortName = shortHostname(device.hostname());
        Optional<DeviceIdentity> known = devices.findByProviderAndExternalId(provider, device.externalId());
        UUID assetId;
        if (known.isPresent()) {
            assetId = known.get().getAssetId();
            counters.matched++;
        } else {
            Match matched = matchExisting(device, shortName);
            if (matched.ambiguous()) {
                return Optional.empty();
            }
            if (matched.assetId() != null) {
                assetId = matched.assetId();
                counters.matched++;
            } else {
                assetId = createHost(tenant, provider, device, now).getId();
                counters.created++;
            }
        }
        DeviceIdentity identity = known.orElseGet(() -> {
            DeviceIdentity created = new DeviceIdentity();
            created.setTenant(tenant);
            created.setProvider(provider);
            created.setExternalId(device.externalId());
            return created;
        });
        identity.setAssetId(assetId);
        identity.setHostname(truncate(device.hostname(), 255));
        identity.setNormalizedHostname(shortName);
        identity.setSerialNumber(blank(device.serialNumber()) ? null : truncate(device.serialNumber().trim(), 255));
        identity.setOsName(truncate(device.osName(), 255));
        identity.setLastSeenAt(now);
        devices.save(identity);
        return Optional.of(assetId);
    }

    /** A single matching asset, no match, or an ambiguous match that must not be guessed. */
    private record Match(UUID assetId, boolean ambiguous) {
        static final Match NONE = new Match(null, false);
        static final Match AMBIGUOUS = new Match(null, true);
    }

    private Match matchExisting(PatchSnapshot.Device device, String shortName) {
        if (!blank(device.serialNumber())) {
            Set<UUID> bySerial = new LinkedHashSet<>();
            devices.findBySerialNumber(device.serialNumber().trim()).forEach(d -> bySerial.add(d.getAssetId()));
            if (bySerial.size() == 1) return new Match(bySerial.iterator().next(), false);
            if (bySerial.size() > 1) return Match.AMBIGUOUS;
        }
        if (shortName == null) return Match.NONE;
        Set<UUID> byName = new LinkedHashSet<>();
        devices.findByNormalizedHostname(shortName).forEach(d -> byName.add(d.getAssetId()));
        assets.findHostsByShortName(shortName).forEach(a -> byName.add(a.getId()));
        if (byName.size() == 1) return new Match(byName.iterator().next(), false);
        if (byName.size() > 1) return Match.AMBIGUOUS;
        return Match.NONE;
    }

    private Asset createHost(Tenant tenant, PatchProviderType provider, PatchSnapshot.Device device, Instant now) {
        Asset asset = new Asset();
        asset.setTenant(tenant);
        asset.setType(AssetType.HOST);
        asset.setIdentifier("patch-device:" + provider.name().toLowerCase(Locale.ROOT) + ":" + truncate(device.externalId(), 200));
        asset.setName(blank(device.hostname()) ? device.externalId() : truncate(device.hostname().trim(), 255));
        asset.setState(AssetState.ACTIVE);
        asset.setLastCmdbSyncAt(now);
        Asset saved = assets.save(asset);
        // Hosts need a CI so the host inventory detail page can load them, as for EC2 and GCP VMs.
        Ci ci = new Ci();
        ci.setTenant(tenant);
        ci.setAsset(saved);
        ci.setSysId(saved.getIdentifier());
        ci.setDisplayName(saved.getName());
        ci.setLastCmdbSyncAt(now);
        ci.touch();
        cis.save(ci);
        return saved;
    }

    // ── Patches ──────────────────────────────────────────────────────────────────────────────

    private UUID upsertPatch(Tenant tenant, PatchProviderType provider, PatchSnapshot.Patch patch, Instant now,
                             KbCveResolver.Lookup kbLookup, Counters counters) {
        String kb = normalizeKb(patch.kbArticle());
        String key = kb != null ? "KB" + kb : provider.name().toLowerCase(Locale.ROOT) + ":" + truncate(patch.externalId(), 180);

        Optional<FixPatchDetail> knownDetail = patchDetails.findByProviderAndExternalId(provider, patch.externalId());
        FixRecord fix = knownDetail.flatMap(detail -> fixes.findById(detail.getFixId()))
                .or(() -> fixes.findByFixTypeAndExternalKey(FixRecord.FixType.PATCH.name(), key))
                .orElseGet(() -> {
                    FixRecord created = new FixRecord();
                    created.setTenant(tenant);
                    created.setFixType(FixRecord.FixType.PATCH.name());
                    created.setExternalKey(key);
                    created.setManaged(true);
                    created.setRecommendationSource(FixRecord.RecommendationSource.PATCH_TOOL.name());
                    created.setRelatedCveIdsJson("[]");
                    created.setSoftwareEntitiesJson("[]");
                    created.setSourceUrlsJson("[]");
                    created.setGeneratedAt(now);
                    return created;
                });
        String title = blank(patch.title()) ? key : patch.title().trim();
        fix.setTitle(truncate(title, 500));
        fix.setSummary(truncate(title, 255));
        if (fix.getEcosystem() == null || patch.ecosystem() != null) {
            fix.setEcosystem(patch.ecosystem() == null ? FixRecord.Ecosystem.CROSS_PLATFORM : patch.ecosystem());
        }
        // Several tools can report one KB with different ratings; keep the most severe.
        fix.setSeverity(maxSeverity(fix.getSeverity(), patch.severity()));
        if (fix.getStatus() == FixRecord.Status.ACTIVE && patch.superseded()) {
            fix.setStatus(FixRecord.Status.SUPERSEDED);
        } else if (fix.getStatus() == FixRecord.Status.SUPERSEDED && !patch.superseded()) {
            fix.setStatus(FixRecord.Status.ACTIVE);
        }

        Set<String> vendorCves = new LinkedHashSet<>();
        for (String cve : patch.cves() == null ? List.<String>of() : patch.cves()) {
            String normalized = cve == null ? null : cve.trim().toUpperCase(Locale.ROOT);
            if (normalized != null && CVE.matcher(normalized).matches()) vendorCves.add(normalized);
        }
        List<String> mapped = kb == null ? List.of() : kbLookup.cvesFor(kb);
        if (fix.getCveId() == null) {
            fix.setCveId(!vendorCves.isEmpty() ? vendorCves.iterator().next() : mapped.isEmpty() ? null : mapped.get(0));
        }
        FixRecord saved = fixes.save(fix);
        counters.patches++;

        for (String cve : vendorCves) counters.cveLinks += link(tenant, saved.getId(), cve, "VENDOR_STATED", "HIGH");
        for (String cve : mapped) counters.cveLinks += link(tenant, saved.getId(), cve, "KB_MAPPING", "MEDIUM");

        FixPatchDetail detail = knownDetail.orElseGet(() -> {
            FixPatchDetail created = new FixPatchDetail();
            created.setTenant(tenant);
            created.setProvider(provider);
            created.setExternalId(truncate(patch.externalId(), 255));
            return created;
        });
        detail.setFixId(saved.getId());
        detail.setKbArticle(kb == null ? null : "KB" + kb);
        detail.setBulletinId(truncate(patch.bulletinId(), 64));
        detail.setVendor(truncate(patch.vendor(), 255));
        detail.setProduct(truncate(patch.product(), 255));
        detail.setClassification(truncate(patch.classification(), 128));
        detail.setVendorSeverity(truncate(patch.vendorSeverity(), 64));
        detail.setReleaseDate(patch.releaseDate());
        detail.setSuperseded(patch.superseded());
        detail.setInfoUrl(httpsUrlOrNull(patch.infoUrl()));
        detail.setLastSeenAt(now);
        patchDetails.save(detail);
        return saved.getId();
    }

    private int link(Tenant tenant, UUID fixId, String cve, String source, String confidence) {
        Optional<FixRecordCve> existing = fixCves.findByFixIdAndCveId(fixId, cve);
        if (existing.isPresent()) {
            // A tool stating the CVE outranks an inferred KB mapping.
            if ("VENDOR_STATED".equals(source) && !"VENDOR_STATED".equals(existing.get().getSource())) {
                existing.get().setSource(source);
                existing.get().setConfidence(confidence);
                fixCves.save(existing.get());
            }
            return 0;
        }
        FixRecordCve created = new FixRecordCve();
        created.setTenant(tenant);
        created.setFixId(fixId);
        created.setCveId(cve);
        created.setSource(source);
        created.setConfidence(confidence);
        created.setCreatedAt(Instant.now());
        fixCves.save(created);
        return 1;
    }

    // ── Deployments and per-asset state ──────────────────────────────────────────────────────

    private UUID upsertDeployment(Tenant tenant, PatchProviderType provider, PatchSnapshot.Deployment deployment, Instant now) {
        PatchDeployment row = deployments.findByProviderAndExternalId(provider, deployment.externalId()).orElseGet(() -> {
            PatchDeployment created = new PatchDeployment();
            created.setTenant(tenant);
            created.setProvider(provider);
            created.setExternalId(truncate(deployment.externalId(), 255));
            return created;
        });
        row.setName(truncate(deployment.name(), 500));
        row.setState(truncate(deployment.state(), 64));
        row.setTargetName(truncate(deployment.targetName(), 500));
        row.setStartsAt(deployment.startsAt());
        row.setDeadlineAt(deployment.deadlineAt());
        row.setLastSeenAt(now);
        return deployments.save(row).getId();
    }

    private void upsertStatus(Tenant tenant, PatchProviderType provider, UUID fixId, UUID assetId,
                              PatchSnapshot.Status status, UUID deploymentId, Instant now, Counters counters) {
        Optional<FixAsset> existing = fixAssets.findByFixIdAndAssetIdAndProvider(fixId, assetId, provider.name());
        FixAsset row = existing.orElseGet(() -> {
            FixAsset created = new FixAsset();
            created.setTenant(tenant);
            created.setFixId(fixId);
            created.setAssetId(assetId);
            created.setProvider(provider.name());
            created.setFirstDetectedAt(now);
            return created;
        });
        FixAssetStatus previous = existing.map(FixAsset::getStatus).orElse(null);
        row.setStatus(status.status());
        row.setDeploymentId(deploymentId);
        row.setScheduledAt(status.scheduledAt());
        row.setDeadlineAt(status.deadlineAt());
        row.setInstalledAt(status.status() == FixAssetStatus.INSTALLED
                ? (status.installedAt() != null ? status.installedAt() : row.getInstalledAt() != null ? row.getInstalledAt() : now)
                : null);
        row.setErrorCode(truncate(status.errorCode(), 128));
        row.setLastReportedAt(now);
        FixAsset saved = fixAssets.save(row);
        counters.statuses++;
        if (previous != status.status()) {
            FixAssetEvent event = new FixAssetEvent();
            event.setTenant(tenant);
            event.setFixAssetId(saved.getId());
            event.setFromStatus(previous == null ? null : previous.name());
            event.setToStatus(status.status().name());
            event.setProvider(provider.name());
            event.setOccurredAt(now);
            events.save(event);
            counters.changes++;
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────

    static String shortHostname(String hostname) {
        if (blank(hostname)) return null;
        String trimmed = hostname.trim().toLowerCase(Locale.ROOT);
        int backslash = trimmed.lastIndexOf('\\');
        if (backslash >= 0) trimmed = trimmed.substring(backslash + 1);
        int dot = trimmed.indexOf('.');
        String shortName = dot > 0 ? trimmed.substring(0, dot) : trimmed;
        return shortName.isBlank() ? null : truncate(shortName, 255);
    }

    static String normalizeKb(String kb) {
        if (kb == null) return null;
        String digits = kb.trim().toUpperCase(Locale.ROOT).replaceFirst("^KB", "");
        return digits.matches("\\d{6,8}") ? digits : null;
    }

    static String maxSeverity(String current, String candidate) {
        String a = current == null ? null : current.toUpperCase(Locale.ROOT);
        String b = candidate == null ? null : candidate.toUpperCase(Locale.ROOT);
        if (b == null || !SEVERITY_RANK.containsKey(b)) return a;
        if (a == null || !SEVERITY_RANK.containsKey(a)) return b;
        return SEVERITY_RANK.get(b) > SEVERITY_RANK.get(a) ? b : a;
    }

    /** Only https links from a tool are kept, so a tool-supplied URL cannot become a javascript: link. */
    static String httpsUrlOrNull(String url) {
        if (url == null) return null;
        String trimmed = url.trim();
        return trimmed.regionMatches(true, 0, "https://", 0, 8) && trimmed.length() <= 1000 ? trimmed : null;
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private static String safe(String value) {
        return blank(value) ? "(unnamed)" : truncate(value, 80);
    }

    static String truncate(String value, int max) {
        if (value == null) return null;
        return value.length() <= max ? value : value.substring(0, max);
    }

    private static final class Counters {
        int matched;
        int created;
        int skipped;
        int patches;
        int cveLinks;
        int deployments;
        int statuses;
        int changes;
    }
}
