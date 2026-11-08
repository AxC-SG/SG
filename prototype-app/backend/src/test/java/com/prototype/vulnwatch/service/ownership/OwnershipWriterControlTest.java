package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/** Plan §7.6: only the namespace service writes teams and aliases; no other main class may issue that SQL. */
class OwnershipWriterControlTest {

    private static final Pattern TEAM_WRITE = Pattern.compile(
            "(?is)\\b(insert\\s+into|update|delete\\s+from)\\s+(\\$\\{tenantSchema}\\.|\\w+\\.)?(team|team_alias)\\b(?!_)");
    private static final Path MAIN = Path.of("src/main/java");
    private static final Path ALLOWED = MAIN.resolve("com/prototype/vulnwatch/service/ownership/TeamNamespaceService.java");

    @Test
    void onlyTeamNamespaceServiceWritesTeamsAndAliases() throws IOException {
        List<Path> offenders;
        try (Stream<Path> files = Files.walk(MAIN)) {
            offenders = files.filter(p -> p.toString().endsWith(".java")).filter(p -> !p.equals(ALLOWED))
                    .filter(p -> {
                        try {
                            return TEAM_WRITE.matcher(Files.readString(p)).find();
                        } catch (IOException ex) {
                            throw new IllegalStateException(ex);
                        }
                    }).toList();
        }
        assertThat(offenders).isEmpty();
    }

    @Test
    void patternRecognisesTeamWrites() {
        assertThat(TEAM_WRITE.matcher("INSERT INTO team (id)").find()).isTrue();
        assertThat(TEAM_WRITE.matcher("update team_alias set").find()).isTrue();
        assertThat(TEAM_WRITE.matcher("DELETE FROM tenant_x.team WHERE").find()).isTrue();
        assertThat(TEAM_WRITE.matcher("INSERT INTO team_member (id)").find()).isFalse();
        assertThat(TEAM_WRITE.matcher("update teams set").find()).isFalse();
    }
}
