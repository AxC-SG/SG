package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.AssetType;
import java.util.Locale;
import org.springframework.stereotype.Component;
import org.w3c.dom.Element;

/**
 * Derives the asset a BOM describes from the document itself, so a pipeline does not have to
 * restate it. Mirrors what the BOM Management upload form extracts in the browser.
 *
 * <p>The identifier deliberately drops the component version: it is the asset's durable identity,
 * and a per-release identifier would make every build a new asset instead of a new version of the
 * same one. A caller that needs a different grouping passes {@code assetIdentifier} explicitly.
 */
@Component
public class BomDocumentMetadataExtractor {

    public record DocumentMetadata(AssetType assetType, String assetName, String assetIdentifier, String supplier) {
    }

    private static final DocumentMetadata EMPTY = new DocumentMetadata(null, null, null, null);

    private final SbomParserService parser;
    private final ObjectMapper objectMapper;

    public BomDocumentMetadataExtractor(SbomParserService parser, ObjectMapper objectMapper) {
        this.parser = parser;
        this.objectMapper = objectMapper;
    }

    public DocumentMetadata extract(byte[] content) {
        try {
            if (isXml(content)) {
                JsonNode spdx = parser.readSpdxXml(content);
                if (spdx != null) {
                    return fromSpdx(spdx);
                }
                return fromCycloneDxXml(parser.buildXmlDocument(content).getDocumentElement());
            }
            JsonNode root = objectMapper.readTree(content);
            if (root == null || !root.isObject()) {
                return EMPTY;
            }
            JsonNode nested = root.path("sbom");
            root = nested.isObject() ? nested : root;
            return root.has("spdxVersion") || root.has("packages") ? fromSpdx(root) : fromCycloneDx(root);
        } catch (Exception e) {
            // Unparseable content is reported by the ingestion path; here it only means
            // nothing could be derived.
            return EMPTY;
        }
    }

    private DocumentMetadata fromCycloneDx(JsonNode root) {
        JsonNode component = root.path("metadata").path("component");
        JsonNode supplier = root.path("metadata").path("supplier");
        if (supplier.isMissingNode()) {
            supplier = root.path("metadata").path("manufacturer");
        }
        return build(
                component.path("type").asText(null),
                component.path("name").asText(null),
                component.path("purl").asText(null),
                supplier.path("name").asText(null));
    }

    private DocumentMetadata fromCycloneDxXml(Element root) {
        Element metadata = child(root, "metadata");
        Element component = metadata == null ? null : child(metadata, "component");
        if (component == null) {
            return EMPTY;
        }
        Element supplier = child(metadata, "supplier");
        if (supplier == null) {
            supplier = child(metadata, "manufacturer");
        }
        return build(
                component.getAttribute("type"),
                childText(component, "name"),
                childText(component, "purl"),
                supplier == null ? null : childText(supplier, "name"));
    }

    private DocumentMetadata fromSpdx(JsonNode root) {
        JsonNode packages = root.path("packages");
        JsonNode primary = null;
        if (packages.isArray()) {
            for (JsonNode pkg : packages) {
                String id = pkg.path("SPDXID").asText("");
                if ("SPDXRef-Package".equals(id) || "SPDXRef-RootPackage".equals(id)) {
                    primary = pkg;
                    break;
                }
            }
            if (primary == null && packages.size() > 0) {
                primary = packages.get(0);
            }
        }
        String name = primary == null ? null : primary.path("name").asText(null);
        if (name == null || name.isBlank()) {
            name = root.path("name").asText(null);
        }
        String purl = null;
        if (primary != null && primary.path("externalRefs").isArray()) {
            for (JsonNode ref : primary.path("externalRefs")) {
                if ("purl".equalsIgnoreCase(ref.path("referenceType").asText(""))) {
                    purl = ref.path("referenceLocator").asText(null);
                    break;
                }
            }
        }
        String supplier = primary == null ? null : primary.path("supplier").asText(null);
        if (supplier != null) {
            supplier = supplier.replaceFirst("(?i)^(organization|person):\\s*", "").trim();
            if (supplier.isBlank() || "NOASSERTION".equalsIgnoreCase(supplier)) {
                supplier = null;
            }
        }
        return build("application", name, purl, supplier);
    }

    private DocumentMetadata build(String componentType, String name, String purl, String supplier) {
        String cleanName = blankToNull(name);
        String identifier = identifierFor(purl, cleanName);
        return new DocumentMetadata(assetTypeFor(componentType), cleanName, identifier, blankToNull(supplier));
    }

    private static AssetType assetTypeFor(String componentType) {
        String type = componentType == null ? "" : componentType.toLowerCase(Locale.ROOT);
        return switch (type) {
            case "container" -> AssetType.CONTAINER_IMAGE;
            case "device", "firmware" -> AssetType.HOST;
            default -> AssetType.APPLICATION;
        };
    }

    /** purl without its version, qualifiers and subpath; otherwise a generic purl from the name. */
    static String identifierFor(String purl, String name) {
        String cleaned = blankToNull(purl);
        if (cleaned != null) {
            int cut = cleaned.length();
            for (char marker : new char[] {'@', '?', '#'}) {
                int at = cleaned.indexOf(marker, "pkg:".length());
                if (at >= 0 && at < cut) {
                    cut = at;
                }
            }
            return cleaned.substring(0, cut);
        }
        return name == null ? null : "pkg:generic/" + name.toLowerCase(Locale.ROOT).replaceAll("\\s+", "-");
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static boolean isXml(byte[] content) {
        int i = 0;
        while (content != null && i < content.length
                && (content[i] == 0x20 || content[i] == 0x09 || content[i] == 0x0A || content[i] == 0x0D)) {
            i++;
        }
        return content != null && i < content.length && content[i] == '<';
    }

    private static Element child(Element parent, String localName) {
        for (var node = parent.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Element element && localName.equals(
                    element.getLocalName() != null ? element.getLocalName() : element.getNodeName())) {
                return element;
            }
        }
        return null;
    }

    private static String childText(Element parent, String localName) {
        Element child = child(parent, localName);
        return child == null ? null : blankToNull(child.getTextContent());
    }
}
