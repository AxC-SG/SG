package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/** Plan §7.6: each ownership table has exactly one writer; no other main class may issue write SQL against it. */
class OwnershipWriterControlTest {

    private static final Path MAIN = Path.of("src/main/java");
    private static final Path PKG = MAIN.resolve("com/prototype/vulnwatch/service/ownership");
    private static final Path NO_WRITER = Path.of("<none>");
    private static final Map<String, Path> WRITERS = Map.ofEntries(
            Map.entry("ownership_resolution_queue", PKG.resolve("OwnershipResolutionService.java")),
            Map.entry("identity_source", PKG.resolve("DirectoryService.java")),
            Map.entry("directory_user", PKG.resolve("DirectoryService.java")),
            Map.entry("directory_group", PKG.resolve("DirectoryService.java")),
            Map.entry("directory_group_member", PKG.resolve("DirectoryService.java")),
            Map.entry("directory_search_token", PKG.resolve("DirectoryService.java")),
            Map.entry("external_identity", PKG.resolve("DirectoryService.java")),
            Map.entry("external_group", PKG.resolve("DirectoryService.java")),
            Map.entry("identity_import_run", PKG.resolve("DirectoryImportService.java")),
            Map.entry("team", PKG.resolve("TeamNamespaceService.java")),
            Map.entry("team_alias", PKG.resolve("TeamNamespaceService.java")),
            Map.entry("ownership_subject", PKG.resolve("OwnershipSubjectService.java")),
            Map.entry("ownership_subject_edge", PKG.resolve("OwnershipSubjectService.java")),
            Map.entry("ownership_claim", PKG.resolve("OwnershipClaimService.java")),
            Map.entry("ownership_assignment", PKG.resolve("OwnershipResolutionService.java")),
            Map.entry("ownership_review_item", PKG.resolve("OwnershipReviewService.java")),
            Map.entry("ownership_event", PKG.resolve("OwnershipEvents.java")),
            Map.entry("ownership_effective_cache", PKG.resolve("OwnershipEffectiveCacheService.java")),
            Map.entry("ownership_cache_invalidation", PKG.resolve("OwnershipEffectiveCacheService.java")));

    static Pattern writePattern(String table) {
        return Pattern.compile("(?is)\\b(insert\\s+into|update|delete\\s+from)\\s+(\\$\\{tenantSchema}\\.|\\w+\\.)?" + table + "\\b(?!_)");
    }

    @Test
    void everyOwnershipTableHasExactlyOneWriter() throws IOException {
        List<Path> sources;
        try (Stream<Path> files = Files.walk(MAIN)) {
            sources = files.filter(p -> p.toString().endsWith(".java")).toList();
        }
        List<String> offenders = new ArrayList<>();
        for (Path source : sources) {
            String text = Files.readString(source);
            WRITERS.forEach((table, writer) -> {
                if (!source.equals(writer) && writePattern(table).matcher(text).find()) offenders.add(table + " <- " + source);
            });
        }
        assertThat(offenders).isEmpty();
        WRITERS.values().stream().filter(p -> p != NO_WRITER).forEach(p -> assertThat(p).exists());
    }

    @Test
    void patternRecognisesWritesWithoutMatchingLongerTableNames() {
        assertThat(writePattern("team").matcher("INSERT INTO team (id)").find()).isTrue();
        assertThat(writePattern("team_alias").matcher("update team_alias set").find()).isTrue();
        assertThat(writePattern("team").matcher("DELETE FROM tenant_x.team WHERE").find()).isTrue();
        assertThat(writePattern("team").matcher("INSERT INTO team_member (id)").find()).isFalse();
        assertThat(writePattern("team").matcher("update teams set").find()).isFalse();
        assertThat(writePattern("ownership_subject").matcher("INSERT INTO ownership_subject_edge (id)").find()).isFalse();
        assertThat(writePattern("ownership_subject").matcher("UPDATE ownership_subject SET").find()).isTrue();
    }
}
