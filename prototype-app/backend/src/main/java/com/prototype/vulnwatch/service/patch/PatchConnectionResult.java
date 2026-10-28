package com.prototype.vulnwatch.service.patch;

import java.util.List;

/** Outcome of a connection test, with each individual check reported. */
public record PatchConnectionResult(String status, String message, List<Check> checks) {

    public record Check(String name, boolean passed, boolean required, String detail) {}

    public static PatchConnectionResult failed(String message) {
        return new PatchConnectionResult("FAILED", message, List.of());
    }

    /** SUCCESS, SUCCESS_WITH_WARNINGS when only optional checks failed, else FAILED. */
    public static PatchConnectionResult of(List<Check> checks, String successMessage) {
        boolean requiredFailed = checks.stream().anyMatch(c -> c.required() && !c.passed());
        boolean optionalFailed = checks.stream().anyMatch(c -> !c.required() && !c.passed());
        if (requiredFailed) {
            String failedNames = String.join(", ", checks.stream().filter(c -> c.required() && !c.passed()).map(Check::name).toList());
            return new PatchConnectionResult("FAILED", "Failed checks: " + failedNames + ".", checks);
        }
        return new PatchConnectionResult(optionalFailed ? "SUCCESS_WITH_WARNINGS" : "SUCCESS", successMessage, checks);
    }
}
