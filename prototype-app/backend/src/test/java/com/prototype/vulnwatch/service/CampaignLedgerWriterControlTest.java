package com.prototype.vulnwatch.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * Phase 0B §4.2/§4.4: {@code campaign_findings} is written only by {@link CampaignLedger}, which only inserts. Nothing
 * updates a member (so the owner-at-add snapshot is immutable without a trigger) and nothing deletes one.
 */
class CampaignLedgerWriterControlTest {

    private static final Path MAIN = Path.of("src/main/java");
    private static final Path LEDGER = MAIN.resolve("com/prototype/vulnwatch/service/CampaignLedger.java");
    private static final Pattern INSERT = Pattern.compile("(?is)\\binsert\\s+into\\s+(\\$\\{tenantSchema}\\.|\\w+\\.)?campaign_findings\\b");
    private static final Pattern UPDATE_OR_DELETE = Pattern.compile(
            "(?is)\\b(update|delete\\s+from)\\s+(only\\s+)?(\\$\\{tenantSchema}\\.|\\w+\\.)?campaign_findings\\b");
    private static final Pattern AT_ADD_COLUMN = Pattern.compile(
            "(?is)\\bset\\b[^;]{0,400}?\\b(owner_team_id_at_add|ownership_assignment_id_at_add|ownership_status_at_add)\\s*=");

    @Test
    void onlyTheLedgerInsertsMembersAndNothingUpdatesOrDeletesThem() throws IOException {
        List<String> offenders = new ArrayList<>();
        try (Stream<Path> files = Files.walk(MAIN)) {
            for (Path source : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                String text = Files.readString(source);
                if (!source.equals(LEDGER) && INSERT.matcher(text).find()) offenders.add("insert <- " + source);
                if (UPDATE_OR_DELETE.matcher(text).find()) offenders.add("update/delete <- " + source);
                if (AT_ADD_COLUMN.matcher(text).find()) offenders.add("at-add column update <- " + source);
            }
        }
        assertThat(offenders).isEmpty();
        assertThat(INSERT.matcher(Files.readString(LEDGER)).find()).as("the ledger insert must be detected").isTrue();
    }

    @Test
    void patternsRecogniseWrites() {
        assertThat(UPDATE_OR_DELETE.matcher("UPDATE campaign_findings SET added_by = 'x'").find()).isTrue();
        assertThat(UPDATE_OR_DELETE.matcher("delete from tenant_a.campaign_findings where").find()).isTrue();
        assertThat(UPDATE_OR_DELETE.matcher("UPDATE campaign_findings_archive SET").find()).isFalse();
        assertThat(AT_ADD_COLUMN.matcher("UPDATE x SET ownership_status_at_add = 'OWNED'").find()).isTrue();
    }
}
