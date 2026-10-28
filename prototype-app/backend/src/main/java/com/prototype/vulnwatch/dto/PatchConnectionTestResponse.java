package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;

public record PatchConnectionTestResponse(
        String status,
        String message,
        List<Check> checks,
        Instant testedAt
) {
    public record Check(String name, boolean passed, boolean required, String detail) {}
}
