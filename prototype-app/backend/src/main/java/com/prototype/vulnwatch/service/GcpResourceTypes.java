package com.prototype.vulnwatch.service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The GCP resource types Cloud Discovery collects, keyed by the stable Scout name stored on
 * targets and on {@code assets.cloud_resource_type}.
 *
 * <p>{@link #COMPUTE_INSTANCE} is read from the Compute API (plus VM Manager packages) and lands
 * as a HOST asset; every other type comes from Cloud Asset Inventory and lands as a
 * CLOUD_RESOURCE asset.
 */
public final class GcpResourceTypes {

    public static final String COMPUTE_INSTANCE = "COMPUTE_INSTANCE";

    private static final Map<String, List<String>> ASSET_TYPES;

    static {
        Map<String, List<String>> types = new LinkedHashMap<>();
        types.put(COMPUTE_INSTANCE, List.of("compute.googleapis.com/Instance"));
        types.put("GKE_CLUSTER", List.of("container.googleapis.com/Cluster"));
        types.put("CLOUD_RUN_SERVICE", List.of("run.googleapis.com/Service"));
        types.put("CLOUD_FUNCTION", List.of("cloudfunctions.googleapis.com/CloudFunction",
                "cloudfunctions.googleapis.com/Function"));
        types.put("CLOUD_SQL_INSTANCE", List.of("sqladmin.googleapis.com/Instance"));
        types.put("STORAGE_BUCKET", List.of("storage.googleapis.com/Bucket"));
        types.put("ARTIFACT_REGISTRY_REPOSITORY", List.of("artifactregistry.googleapis.com/Repository"));
        ASSET_TYPES = java.util.Collections.unmodifiableMap(types);
    }

    private GcpResourceTypes() { }

    public static List<String> all() {
        return List.copyOf(ASSET_TYPES.keySet());
    }

    /** Validates and normalizes a requested type list; empty means every supported type. */
    public static List<String> normalize(Collection<String> requested) {
        if (requested == null || requested.isEmpty()) {
            return all();
        }
        List<String> normalized = new ArrayList<>();
        for (String type : requested) {
            String key = type == null ? "" : type.trim().toUpperCase(Locale.ROOT);
            if (!ASSET_TYPES.containsKey(key)) {
                throw new IllegalArgumentException("Unsupported GCP resource type: " + type
                        + ". Supported: " + String.join(", ", ASSET_TYPES.keySet()));
            }
            if (!normalized.contains(key)) {
                normalized.add(key);
            }
        }
        return normalized;
    }

    /** Cloud Asset types for the non-VM keys in {@code keys}. */
    public static Map<String, List<String>> cloudAssetTypes(Collection<String> keys) {
        Map<String, List<String>> result = new LinkedHashMap<>();
        for (String key : keys) {
            if (!COMPUTE_INSTANCE.equals(key) && ASSET_TYPES.containsKey(key)) {
                result.put(key, ASSET_TYPES.get(key));
            }
        }
        return result;
    }

    /** IAM permissions a target needs for the given types, for the per-permission connection test. */
    public static List<String> requiredPermissions(Collection<String> keys) {
        List<String> permissions = new ArrayList<>(List.of("resourcemanager.projects.get"));
        if (keys.contains(COMPUTE_INSTANCE)) {
            permissions.add("compute.instances.list");
            permissions.add("osconfig.inventories.list");
        }
        if (!cloudAssetTypes(keys).isEmpty()) {
            permissions.add("cloudasset.assets.searchAllResources");
        }
        return permissions;
    }

    /** Permissions whose absence only degrades the result (packages), rather than failing it. */
    public static boolean isOptional(String permission) {
        return "osconfig.inventories.list".equals(permission);
    }
}
