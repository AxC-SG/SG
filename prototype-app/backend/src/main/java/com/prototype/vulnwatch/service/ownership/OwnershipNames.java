package com.prototype.vulnwatch.service.ownership;

import java.text.Normalizer;
import java.util.Locale;
import java.util.regex.Pattern;

/** Normalization for the shared team-name/alias namespace and for directory-group name keys. */
public final class OwnershipNames {

    public static final int MAX_LENGTH = 200;
    private static final Pattern WHITESPACE = Pattern.compile("\\s+");
    private static final Pattern CONTROL = Pattern.compile("\\p{Cntrl}");

    private OwnershipNames() { }

    /** Trimmed, whitespace-collapsed display form; rejects blank, over-long or control-character input. */
    public static String display(String value) {
        if (value == null) throw new IllegalArgumentException("A name is required");
        String cleaned = WHITESPACE.matcher(Normalizer.normalize(value, Normalizer.Form.NFKC).strip()).replaceAll(" ");
        if (cleaned.isEmpty()) throw new IllegalArgumentException("A name is required");
        if (cleaned.length() > MAX_LENGTH) throw new IllegalArgumentException("Names are limited to " + MAX_LENGTH + " characters");
        if (CONTROL.matcher(cleaned).find()) throw new IllegalArgumentException("Names cannot contain control characters");
        return cleaned;
    }

    /** Case-insensitive key; two values with the same key collide in the namespace. */
    public static String key(String value) {
        return display(value).toLowerCase(Locale.ROOT);
    }
}
