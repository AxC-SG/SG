package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BomSourceCompleteness;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.dto.BomIngestResponse;
import com.prototype.vulnwatch.dto.BomIngestStatusResponse;
import com.prototype.vulnwatch.service.BomApiIngestService;
import com.prototype.vulnwatch.service.BomIngestException;
import java.util.Locale;
import java.util.UUID;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Pipeline-facing BOM ingestion: the document is the request body and the Content-Type names its
 * serialization (JSON or XML). Accepted from a tenant ingest key as well as from tenant admins.
 */
@RestController
@RequestMapping("/api/bom/ingest")
public class BomIngestController {

    private static final String INGEST_ROLES = "hasAnyRole('INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','BOM_INGEST_KEY')";
    private static final String STATUS_ROLES =
            "hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR','BOM_INGEST_KEY')";

    private final BomApiIngestService ingestService;

    public BomIngestController(BomApiIngestService ingestService) {
        this.ingestService = ingestService;
    }

    /**
     * POST /api/bom/ingest?bomType=SBOM
     * Everything except {@code bomType} is optional: the asset is derived from the document, and
     * repeat pushes replace the previous version of the same source.
     */
    @PostMapping
    @PreAuthorize(INGEST_ROLES)
    public ResponseEntity<BomIngestResponse> ingest(
            @RequestBody(required = false) byte[] body,
            @RequestHeader(value = HttpHeaders.CONTENT_TYPE, required = false) String contentType,
            @RequestParam(required = false) String bomType,
            @RequestParam(required = false) String assetType,
            @RequestParam(required = false) String assetName,
            @RequestParam(required = false) String assetIdentifier,
            @RequestParam(required = false) String supplier,
            @RequestParam(required = false) String correlator,
            @RequestParam(required = false) String pipeline,
            @RequestParam(required = false) String buildId,
            @RequestParam(required = false) String completeness,
            @RequestParam(required = false) String environment
    ) {
        BomApiIngestService.Request request = new BomApiIngestService.Request(
                parse(BomType.class, "bomType", bomType, true),
                parse(AssetType.class, "assetType", assetType, false),
                assetName, assetIdentifier, supplier, correlator, pipeline, buildId,
                parse(BomSourceCompleteness.class, "completeness", completeness, false));
        String env;
        try {
            env = com.prototype.vulnwatch.service.cbom.CbomGateService.environment(environment);
        } catch (IllegalArgumentException e) {
            throw new BomIngestException(HttpStatus.BAD_REQUEST, "INVALID_PARAMETER", e.getMessage());
        }
        BomIngestResponse response = ingestService.ingest(body, contentType, request);
        if (gates != null && request.bomType() == BomType.CBOM && response.bomId() != null) {
            response = response.withGate(gates.issue(response.bomId(), env, "ingest:" + (pipeline == null ? "api" : pipeline)), env);
        }
        HttpStatus status = "CREATED".equals(response.action()) ? HttpStatus.CREATED : HttpStatus.OK;
        return ResponseEntity.status(status).body(response);
    }

    @GetMapping("/{bomId}/status")
    @PreAuthorize(STATUS_ROLES)
    public BomIngestStatusResponse status(@PathVariable UUID bomId,
            @RequestHeader(value = GATE_TOKEN_HEADER, required = false) String gateToken) {
        BomIngestStatusResponse status = ingestService.status(bomId);
        if (gateToken == null || gates == null || workspace == null) return status;
        return status.withGate(gates.result(workspace.getWorkspace(), bomId, gateToken));
    }

    /** Header carrying the single-job gate token returned by a CBOM push. */
    public static final String GATE_TOKEN_HEADER = "X-Scout-Gate-Token";

    private com.prototype.vulnwatch.service.cbom.CbomGateService gates;
    private com.prototype.vulnwatch.service.WorkspaceService workspace;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setGates(com.prototype.vulnwatch.service.cbom.CbomGateService gates, com.prototype.vulnwatch.service.WorkspaceService workspace) {
        this.gates = gates;
        this.workspace = workspace;
    }


    private static <E extends Enum<E>> E parse(Class<E> type, String name, String value, boolean required) {
        if (value == null || value.isBlank()) {
            if (required) {
                throw new BomIngestException(HttpStatus.BAD_REQUEST, "INVALID_PARAMETER", name + " is required.");
            }
            return null;
        }
        try {
            return Enum.valueOf(type, value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new BomIngestException(HttpStatus.BAD_REQUEST, "INVALID_PARAMETER",
                    name + " must be one of " + java.util.Arrays.toString(type.getEnumConstants()) + ".");
        }
    }
}
