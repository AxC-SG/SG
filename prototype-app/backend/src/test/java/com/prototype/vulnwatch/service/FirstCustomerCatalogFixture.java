package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.client.NvdApiClient.NvdPage;
import com.prototype.vulnwatch.client.NvdApiClient.NvdRecord;
import com.prototype.vulnwatch.client.NvdApiClient.NvdRule;
import java.time.Instant;
import java.util.List;
import java.util.stream.IntStream;

final class FirstCustomerCatalogFixture {
    static final int PAGE_SIZE = 1000;
    static final int CVES = 400_000;
    private static final Instant DATE = Instant.parse("2025-01-15T00:00:00Z");
    private static final String DESCRIPTION = """
            This synthetic advisory describes a validation error in an application component.
            Supported release families use different version ranges. Install the vendor's updated package
            or disable the optional feature until normal maintenance can be performed.
            """.repeat(3);

    private FirstCustomerCatalogFixture() {}

    static NvdPage page(int start, int total) {
        return new NvdPage(IntStream.range(start, Math.min(start + PAGE_SIZE, total))
                .mapToObj(FirstCustomerCatalogFixture::record).toList(), total, start, PAGE_SIZE);
    }

    private static NvdRecord record(int index) {
        String id = "CVE-2025-" + (100_000 + index);
        String product = "volume_" + index % 20_000;
        String cpe = "cpe:2.3:a:qualification:" + product + ":*:*:*:*:*:*:*:*";
        String match = """
                {"vulnerable":true,"criteria":"%s","versionStartIncluding":"1.0",
                 "versionEndExcluding":"2.0"}
                """.formatted(cpe);
        boolean hasConfiguration = index % 4 == 0;
        String nodes = hasConfiguration
                ? "[{\"operator\":\"OR\",\"negate\":false,\"cpeMatch\":[" + match + "]}]"
                : "[]";
        String raw = """
                {"id":"%s","sourceIdentifier":"qualification@example.test","vulnStatus":"Analyzed",
                 "descriptions":[{"lang":"en","value":"%s"}],
                 "references":[{"url":"https://example.test/advisories/%s","tags":["Vendor Advisory"]}],
                 "configurations":[{"nodes":%s}]}
                """.formatted(id, DESCRIPTION.replace("\n", " "), id, nodes);
        var rule = new NvdRule("cpe", "qualification:" + product, null, "1.0", true,
                "2.0", false, cpe, "qualification", product);
        return new NvdRecord(id, "Qualification advisory " + id, DESCRIPTION, 8.1, "HIGH", "Analyzed",
                "3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "NETWORK", "LOW", "NONE",
                "REQUIRED", "UNCHANGED", 2.8, 5.9, "CWE-20", "[]", "qualification@example.test",
                DATE, DATE, List.of(rule), raw);
    }
}
