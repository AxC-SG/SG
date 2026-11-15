package com.prototype.vulnwatch.service.ownership;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Locale;
import java.util.UUID;

/**
 * The software occurrence key (Phase 0B §3.1, §3.2), shared by every {@code inventory_components} writer and by
 * set-based registration. The writers store {@code ecosystem}, {@code package_name}, {@code version} and {@code purl}
 * with different normalization (the R2 check, §3.9), so the key normalizes for itself: ecosystem, package name and
 * PURL are trimmed and lower-cased, the version is trimmed, and a missing value is the empty string. {@link #SQL} is
 * the same expression for the database; {@code OccurrenceKeyPostgresIntegrationTest} proves the two agree.
 */
public final class OccurrenceKey {

    public static final String SUBJECT_TYPE = "COMPONENT_OCCURRENCE";

    /** {@code source_object_id} for an {@code inventory_components} row aliased {@code ic}. */
    public static final String SQL = "'pkg:' || encode(sha256(convert_to("
            + "lower(btrim(coalesce(ic.ecosystem, ''))) || '|' || lower(btrim(coalesce(ic.package_name, ''))) || '|' || "
            + "btrim(coalesce(ic.version, '')) || '|' || lower(btrim(coalesce(ic.purl, ''))), 'UTF8')), 'hex')";

    private OccurrenceKey() { }

    public static String sourceObjectId(String ecosystem, String packageName, String version, String purl) {
        String material = lower(ecosystem) + "|" + lower(packageName) + "|" + trim(version) + "|" + lower(purl);
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(material.getBytes(StandardCharsets.UTF_8));
            return "pkg:" + HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    public static String contextKey(UUID assetId) {
        return "asset:" + assetId;
    }

    /** PostgreSQL {@code btrim} removes spaces only, so the Java side trims spaces only too. */
    private static String trim(String value) {
        if (value == null) return "";
        int start = 0;
        int end = value.length();
        while (start < end && value.charAt(start) == ' ') start++;
        while (end > start && value.charAt(end - 1) == ' ') end--;
        return value.substring(start, end);
    }

    private static String lower(String value) {
        return trim(value).toLowerCase(Locale.ROOT);
    }
}
