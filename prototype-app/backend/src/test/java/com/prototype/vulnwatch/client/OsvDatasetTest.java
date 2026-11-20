package com.prototype.vulnwatch.client;

import com.prototype.vulnwatch.client.http.OsvApiClient;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class OsvDatasetTest {
    @Test void streamsArchiveIncludingWithdrawalsAndUnknownSchemaFields() throws Exception {
        var bytes=new ByteArrayOutputStream();
        try(var zip=new ZipOutputStream(bytes)) {
            zip.putNextEntry(new ZipEntry("OSV-1.json"));
            zip.write("""
                {"id":"OSV-1","modified":"2026-01-01T00:00:00Z","withdrawn":"2026-01-01T00:00:00Z",
                 "schema_version":"1.7.0","affected":[{"package":{"ecosystem":"Maven","name":"x:y"}}]}
                """.getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        }
        var rest=new RestTemplate();
        var server=MockRestServiceServer.bindTo(rest).build();
        server.expect(requestTo("https://storage.googleapis.com/osv-vulnerabilities/all.zip"))
            .andRespond(withSuccess(bytes.toByteArray(),MediaType.APPLICATION_OCTET_STREAM));
        var records=new ArrayList<OsvApiClient.OsvVulnerability>();
        assertEquals(1,new OsvApiClient(rest).streamDataset(records::add));
        assertNotNull(records.get(0).getWithdrawn());
        assertEquals("Maven",records.get(0).getAffected().get(0).getPackage_info().getEcosystem());
        server.verify();
    }
}
