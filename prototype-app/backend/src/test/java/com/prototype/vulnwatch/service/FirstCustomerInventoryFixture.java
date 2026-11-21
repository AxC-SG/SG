package com.prototype.vulnwatch.service;

import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

final class FirstCustomerInventoryFixture {
    static final int ASSETS = 1_000;
    static final int SOFTWARE_PER_ASSET = 500;
    static final String PROBE_VENDOR = "qualification_probe";
    static final String PROBE_PRODUCT = "rolling_update";

    private FirstCustomerInventoryFixture() {}

    static List<Map<String, String>> host(int host, int products) {
        return IntStream.range(0, products).mapToObj(software -> install(host, software, "1.0")).toList();
    }

    static Map<String, String> install(int host, int software, String version) {
        String vendor = software == 0 && host < 8 ? PROBE_VENDOR : "qualification_vendor_" + software % 25;
        String product = software == 0 && host < 8 ? PROBE_PRODUCT : "pilot_software_" + software;
        return Map.of("sys_id", Integer.toString(10_000 + host), "computer_name", "qualification-host-" + host,
                "display_name", product, "publisher", vendor, "normalized_product", product,
                "normalized_publisher", vendor, "version", version);
    }
}
