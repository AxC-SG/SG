package com.prototype.vulnwatch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Source-level CI tripwire for the single canonical Finding suppression writer. */
class CanonicalSuppressionBoundaryTest {
    private static final String ALLOWED = "CanonicalSuppressionMutationService.java";
    private static final List<String> FORBIDDEN_CALLS = List.of(
            ".setSuppressionReason(",
            ".setSuppressedUntil(",
            ".setSuppressedByRuleId(",
            ".setSuppressedByRuleName(",
            ".setStatus(FindingStatus.SUPPRESSED)"
    );

    @Test
    void onlyCanonicalMutationServiceWritesFindingSuppressionState() throws IOException {
        Path sourceRoot = Path.of("src/main/java/com/prototype/vulnwatch");
        List<String> violations = new ArrayList<>();
        try (var files = Files.walk(sourceRoot)) {
            for (Path file : files.filter(path -> path.toString().endsWith(".java")).toList()) {
                String name = file.getFileName().toString();
                if (ALLOWED.equals(name) || name.equals("OrgCveRecordService.java")
                        || name.equals("SuppressionRuleService.java")) {
                    // The latter two mutate OrgCveRecord, not canonical Finding. Validate their
                    // Finding calls explicitly below so a future Finding writer cannot hide here.
                    if (!name.equals("SuppressionRuleService.java")) continue;
                }
                List<String> lines = Files.readAllLines(file);
                for (int i = 0; i < lines.size(); i++) {
                    String line = lines.get(i);
                    if (FORBIDDEN_CALLS.stream().anyMatch(line::contains)
                            && !(name.equals("SuppressionRuleService.java") && line.contains("record."))) {
                        violations.add(file + ":" + (i + 1) + " " + line.trim());
                    }
                }
            }
        }
        assertEquals(List.of(), violations,
                "Canonical Finding suppression writes must go through " + ALLOWED);
    }
}
