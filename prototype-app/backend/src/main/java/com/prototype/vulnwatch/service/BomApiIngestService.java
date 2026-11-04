package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomSource;
import com.prototype.vulnwatch.domain.BomSourceCompleteness;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.BomIngestResponse;
import com.prototype.vulnwatch.dto.BomIngestStatusResponse;
import com.prototype.vulnwatch.dto.BomIngestionResultResponse;
import com.prototype.vulnwatch.dto.BomInspectionResponse;
import com.prototype.vulnwatch.dto.BomSourceSelector;
import com.prototype.vulnwatch.repo.BomIngestionRecordRepository;
import com.prototype.vulnwatch.repo.BomSourceRepository;
import com.prototype.vulnwatch.util.BomInputLimits;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.InvalidMediaTypeException;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

/**
 * Pipeline-facing BOM ingestion. Reuses {@link BomIngestionOrchestrator} so an API push goes
 * through exactly the same parsing, source and correlation path as an upload.
 *
 * <p>Repeated pushes for the same source replace the previous version. The source identity is the
 * caller's {@code correlator} when given, otherwise the asset identifier, so a pipeline that
 * pushes on every build does not accumulate one source per build. Re-pushing byte-identical
 * content is a no-op that reports UNCHANGED, which makes a retried pipeline step safe.
 */
@Service
public class BomApiIngestService {

    public static final String KEY_ROLE = "BOM_INGEST_KEY";
    static final int MAX_PIPELINE = 80;
    static final int MAX_LABEL = 200;

    public record Request(
            BomType bomType,
            AssetType assetType,
            String assetName,
            String assetIdentifier,
            String supplier,
            String correlator,
            String pipeline,
            String buildId,
            BomSourceCompleteness completeness
    ) {
    }

    private final WorkspaceService workspaceService;
    private final RequestActorService requestActorService;
    private final BomIngestionOrchestrator orchestrator;
    private final SbomParserService parser;
    private final BomDocumentMetadataExtractor metadataExtractor;
    private final BomSourceRepository sourceRepository;
    private final BomIngestionRecordRepository recordRepository;
    private final AuditEventService auditEventService;

    public BomApiIngestService(
            WorkspaceService workspaceService,
            RequestActorService requestActorService,
            BomIngestionOrchestrator orchestrator,
            SbomParserService parser,
            BomDocumentMetadataExtractor metadataExtractor,
            BomSourceRepository sourceRepository,
            BomIngestionRecordRepository recordRepository,
            AuditEventService auditEventService
    ) {
        this.workspaceService = workspaceService;
        this.requestActorService = requestActorService;
        this.orchestrator = orchestrator;
        this.parser = parser;
        this.metadataExtractor = metadataExtractor;
        this.sourceRepository = sourceRepository;
        this.recordRepository = recordRepository;
        this.auditEventService = auditEventService;
    }

    public BomIngestResponse ingest(byte[] body, String contentType, Request request) {
        requireSupportedContentType(contentType);
        if (body == null || body.length == 0) {
            throw new BomIngestException(HttpStatus.BAD_REQUEST, "EMPTY_BODY", "The request body is empty.");
        }
        if (body.length > BomInputLimits.MAX_BOM_BYTES) {
            throw new BomIngestException(HttpStatus.PAYLOAD_TOO_LARGE, "BOM_TOO_LARGE",
                    "BOM exceeds the 50 MB limit.");
        }
        validateLength("pipeline", request.pipeline(), MAX_PIPELINE);
        validateLength("buildId", request.buildId(), MAX_LABEL);
        validateLength("correlator", request.correlator(), MAX_LABEL);

        RequestActor actor = requestActorService.currentActor();
        BomSourceCompleteness completeness = request.completeness() == null
                ? BomSourceCompleteness.PARTIAL : request.completeness();
        if (completeness == BomSourceCompleteness.COMPLETE_ASSET_SOFTWARE && actor.roles().contains(KEY_ROLE)) {
            throw new BomIngestException(HttpStatus.FORBIDDEN, "COMPLETENESS_NOT_PERMITTED",
                    "An ingest key cannot assert complete asset software inventory; "
                            + "that claim needs an inventory administrator.");
        }

        SbomFormat format = detectFormat(body);
        BomDocumentMetadataExtractor.DocumentMetadata derived = metadataExtractor.extract(body);
        AssetType assetType = request.assetType() != null ? request.assetType()
                : derived.assetType() != null ? derived.assetType() : AssetType.APPLICATION;
        String assetName = firstText(request.assetName(), derived.assetName());
        String assetIdentifier = firstText(request.assetIdentifier(), derived.assetIdentifier());
        if (assetName == null || assetIdentifier == null) {
            throw new BomIngestException(HttpStatus.UNPROCESSABLE_ENTITY, "ASSET_NOT_DERIVABLE",
                    "The document does not name the asset it describes. "
                            + "Pass assetName and assetIdentifier.");
        }
        String supplier = firstText(request.supplier(), derived.supplier());

        Tenant tenant = workspaceService.getWorkspace();
        String sourceKey = sourceKey(request.bomType(), request.correlator(), assetIdentifier);
        String checksum = sha256(body);

        BomIngestionRecord unchanged = currentRecordIfIdentical(sourceKey, checksum);
        if (unchanged != null) {
            return unchangedResponse(unchanged);
        }

        String pipeline = trimToNull(request.pipeline());
        String buildLabel = trimToNull(request.buildId()) == null ? null : "build:" + request.buildId().trim();
        String keyReference = actor.roles().contains(KEY_ROLE) ? actor.userId() : null;
        BomSourceSelector selector = new BomSourceSelector(
                null, sourceKey, completeness, actor.roles(), actor.userId());

        BomIngestionResultResponse result;
        try {
            result = orchestrator.ingestFromApi(
                    tenant, request.bomType(), assetType, assetName, assetIdentifier, supplier, body,
                    contentType, pipeline, buildLabel, trimToNull(request.correlator()), keyReference, selector);
        } catch (IOException e) {
            throw classify(e);
        }

        UUID sourceId = recordRepository.findById(result.bomId()).map(BomIngestionRecord::getSourceId).orElse(null);
        auditEventService.record("bom.api_ingest", "bom", String.valueOf(result.bomId()),
                auditDetails(request, result, pipeline));
        return new BomIngestResponse(
                result.bomId(), result.assetId(), sourceId, result.bomType(), result.format(),
                result.formatVersion(), result.documentFormat(), result.supported(), result.warnings(),
                result.componentCount(), result.findingsGenerated(), result.status(), result.action(),
                statusUrl(result.bomId()));
    }

    public BomIngestStatusResponse status(UUID bomId) {
        BomIngestionRecord record = recordRepository.findById(bomId).orElseThrow(() ->
                new BomIngestException(HttpStatus.NOT_FOUND, "BOM_NOT_FOUND", "No BOM with that id."));
        return new BomIngestStatusResponse(
                record.getId(), record.getSourceId(), record.getBomType().name(), record.getStatus().name(),
                record.getComponentCount(), record.getFormat() == null ? null : record.getFormat().name(),
                record.getFormatVersion(), record.getSourceSystem(), buildOf(record.getSourceLabel()),
                record.getSourceReference(), record.getIngestedAt(), record.getSupersededBy());
    }

    private BomIngestionRecord currentRecordIfIdentical(String sourceKey, String checksum) {
        BomSource source = sourceRepository.findBySourceKey(sourceKey).orElse(null);
        if (source == null || source.getCurrentBomId() == null) {
            return null;
        }
        return recordRepository.findById(source.getCurrentBomId())
                .filter(record -> checksum.equals(record.getChecksumSha256()))
                .orElse(null);
    }

    private BomIngestResponse unchangedResponse(BomIngestionRecord record) {
        BomInspectionResponse inspection = parser.inspectResolved(
                record.getFormat() == null ? null : record.getFormat().name(),
                record.getFormatVersion(),
                record.getSpecFamily() == null ? null : record.getSpecFamily().name(),
                record.getDocumentFormat() == null ? null : record.getDocumentFormat().name());
        return new BomIngestResponse(
                record.getId(), record.getAssetId(), record.getSourceId(), record.getBomType().name(),
                record.getFormat() == null ? null : record.getFormat().name(), record.getFormatVersion(),
                record.getDocumentFormat() == null ? null : record.getDocumentFormat().name(),
                inspection.supported(), inspection.warnings(), record.getComponentCount(), 0,
                record.getStatus().name(), "UNCHANGED", statusUrl(record.getId()));
    }

    private SbomFormat detectFormat(byte[] body) {
        SbomFormat format;
        try {
            format = parser.detectFormat(body);
        } catch (IOException e) {
            throw new BomIngestException(HttpStatus.UNPROCESSABLE_ENTITY, "INVALID_DOCUMENT",
                    "The body is not a valid JSON or XML BOM document.");
        }
        if (format == SbomFormat.UNKNOWN) {
            throw new BomIngestException(HttpStatus.UNPROCESSABLE_ENTITY, "UNSUPPORTED_FORMAT",
                    "The document is not a supported CycloneDX or SPDX BOM.");
        }
        return format;
    }

    private BomIngestException classify(IOException e) {
        String message = e.getMessage() == null ? "" : e.getMessage();
        if (BomIngestionOrchestrator.DUPLICATE_BOM_MESSAGE.equals(message)) {
            return new BomIngestException(HttpStatus.CONFLICT, "DUPLICATE_SERIAL_NUMBER",
                    "A different document with this serial number or namespace was already ingested for "
                            + "this source. Generate a new serial number for each build.");
        }
        if (message.toLowerCase(Locale.ROOT).contains("already in progress")) {
            return new BomIngestException(HttpStatus.CONFLICT, "INGEST_IN_PROGRESS", message);
        }
        if (message.contains("No BOM components could be extracted")
                || message.contains("No CBOM cryptographic assets")) {
            return new BomIngestException(HttpStatus.UNPROCESSABLE_ENTITY, "NO_COMPONENTS", message);
        }
        if (message.contains("Unsupported or unrecognized BOM format")) {
            return new BomIngestException(HttpStatus.UNPROCESSABLE_ENTITY, "UNSUPPORTED_FORMAT", message);
        }
        return new BomIngestException(HttpStatus.UNPROCESSABLE_ENTITY, "INGESTION_FAILED",
                message.isBlank() ? "Failed to process the BOM." : message);
    }

    static void requireSupportedContentType(String contentType) {
        if (contentType == null || contentType.isBlank()) {
            throw new BomIngestException(HttpStatus.BAD_REQUEST, "MISSING_CONTENT_TYPE",
                    "Content-Type header is missing.");
        }
        MediaType type;
        try {
            type = MediaType.parseMediaType(contentType);
        } catch (InvalidMediaTypeException e) {
            throw unsupportedContentType();
        }
        String subtype = type.getSubtype().toLowerCase(Locale.ROOT);
        String main = type.getType().toLowerCase(Locale.ROOT);
        boolean json = subtype.equals("json") || subtype.endsWith("+json");
        boolean xml = subtype.equals("xml") || subtype.endsWith("+xml");
        if (!((main.equals("application") || main.equals("text")) && (json || xml))) {
            throw unsupportedContentType();
        }
    }

    private static BomIngestException unsupportedContentType() {
        return new BomIngestException(HttpStatus.BAD_REQUEST, "UNSUPPORTED_CONTENT_TYPE",
                "Unsupported Content-Type. BOM data must be in JSON or XML.");
    }

    static String sourceKey(BomType bomType, String correlator, String assetIdentifier) {
        String identity = trimToNull(correlator) != null
                ? "c:" + correlator.trim()
                : "a:" + assetIdentifier.trim();
        return "api:" + bomType.name() + ":" + identity.toLowerCase(Locale.ROOT);
    }

    private static void validateLength(String name, String value, int max) {
        if (value != null && value.trim().length() > max) {
            throw new BomIngestException(HttpStatus.BAD_REQUEST, "INVALID_PARAMETER",
                    name + " must be at most " + max + " characters.");
        }
    }

    private static String buildOf(String label) {
        return label != null && label.startsWith("build:") ? label.substring("build:".length()) : null;
    }

    private static String statusUrl(UUID bomId) {
        return "/api/bom/ingest/" + bomId + "/status";
    }

    private static String firstText(String preferred, String fallback) {
        String first = trimToNull(preferred);
        return first != null ? first : trimToNull(fallback);
    }

    private static String trimToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static String auditDetails(Request request, BomIngestionResultResponse result, String pipeline) {
        return "{\"bomType\":\"" + request.bomType().name() + "\",\"action\":\"" + result.action()
                + "\",\"componentCount\":" + result.componentCount()
                + ",\"pipeline\":" + jsonString(pipeline)
                + ",\"buildId\":" + jsonString(trimToNull(request.buildId()))
                + ",\"correlator\":" + jsonString(trimToNull(request.correlator())) + "}";
    }

    private static String jsonString(String value) {
        if (value == null) {
            return "null";
        }
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", " ").replace("\r", " ") + "\"";
    }

    private static String sha256(byte[] content) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(content);
            StringBuilder builder = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                builder.append(String.format("%02x", b));
            }
            return builder.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
