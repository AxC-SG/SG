package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.dto.BomInspectionResponse;
import com.prototype.vulnwatch.dto.BomSupportEntryResponse;
import com.prototype.vulnwatch.dto.BomSupportMatrixResponse;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.dto.ParsedComponent;
import com.prototype.vulnwatch.util.BomInputLimits;
import com.prototype.vulnwatch.util.CpeUtil;
import com.prototype.vulnwatch.util.PurlUtil;
import com.prototype.vulnwatch.util.SpdxXmlConverter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Locale;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

@Service
public class SbomParserService {
    private final ObjectMapper objectMapper;

    public SbomParserService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public SbomFormat detectFormat(byte[] content) throws IOException {
        BomInputLimits.checkBytes(content);
        if (isXmlBytes(content)) {
            return detectFormatFromXml(content);
        }
        JsonNode root = normalizeRoot(objectMapper.readTree(content));
        if (root.has("bomFormat") || root.has("components")) {
            return SbomFormat.CYCLONEDX;
        }
        if (root.has("spdxVersion") || root.has("packages")) {
            return SbomFormat.SPDX;
        }
        return SbomFormat.UNKNOWN;
    }

    public List<ParsedComponent> parse(byte[] content) throws IOException {
        BomInputLimits.checkBytes(content);
        if (isXmlBytes(content)) {
            return parseXmlContent(content);
        }
        JsonNode root = normalizeRoot(objectMapper.readTree(content));
        if (root.has("components")) {
            return parseCycloneDx(root);
        }
        if (root.has("packages")) {
            return parseSpdx(root);
        }
        return List.of();
    }

    public BomInspectionResponse inspect(byte[] content) throws IOException {
        SbomFormat format = detectFormat(content);
        String formatVersion = null;
        String specFamily;
        String documentFormat = isXmlBytes(content) ? "XML" : "JSON";
        if (isXmlBytes(content)) {
            String[] xmlMeta = extractXmlVersion(content);
            formatVersion = xmlMeta[1];
        } else {
            JsonNode root = normalizeRoot(objectMapper.readTree(content));
            formatVersion = extractFormatVersion(root, format);
        }
        specFamily = switch (format) {
            case CYCLONEDX -> "CYCLONEDX";
            case SPDX -> "SPDX";
            default -> "UNKNOWN";
        };
        return inspectResolved(format.name(), formatVersion, specFamily, documentFormat);
    }

    public BomInspectionResponse inspectResolved(
            String format,
            String formatVersion,
            String specFamily,
            String documentFormat
    ) {
        String normalizedSpec = specFamily == null ? "UNKNOWN" : specFamily.toUpperCase(Locale.ROOT);
        String normalizedFormat = documentFormat == null ? "UNKNOWN" : documentFormat.toUpperCase(Locale.ROOT);
        List<String> warnings = new ArrayList<>();
        String supportLevel = "UNKNOWN";
        boolean supported = false;
        if ("CYCLONEDX".equals(normalizedSpec)) {
            supportLevel = evaluateSupportLevel(formatVersion, List.of("1.6"), List.of("1.5"), List.of("1.4"));
            supported = !"UNKNOWN".equals(supportLevel);
        } else if ("SPDX".equals(normalizedSpec)) {
            supportLevel = evaluateSupportLevel(formatVersion, List.of("2.3"), List.of("2.2"), List.of("2.1"));
            supported = !"UNKNOWN".equals(supportLevel);
        } else if ("VENDOR".equals(normalizedSpec)) {
            supportLevel = "VENDOR_DEFINED";
            supported = true;
        }
        if (!supported) {
            warnings.add("This BOM spec/version is not in the supported matrix.");
        } else if ("LEGACY".equals(supportLevel)) {
            warnings.add("This BOM uses a legacy spec version. Validate parser output before relying on downstream automation.");
        }
        if (!"JSON".equals(normalizedFormat) && !"XML".equals(normalizedFormat) && !"UNKNOWN".equals(normalizedFormat)) {
            warnings.add("This document format is not currently validated by the parser support matrix.");
        }
        return new BomInspectionResponse(format, formatVersion, normalizedSpec, normalizedFormat, supportLevel, supported, warnings);
    }

    public BomSupportMatrixResponse supportMatrix() {
        return new BomSupportMatrixResponse(List.of(
                new BomSupportEntryResponse("CYCLONEDX", "JSON", "1.6", "CURRENT", true, "Preferred CycloneDX JSON support"),
                new BomSupportEntryResponse("CYCLONEDX", "XML", "1.6", "CURRENT", true, "Preferred CycloneDX XML support"),
                new BomSupportEntryResponse("CYCLONEDX", "JSON", "1.5", "PREVIOUS", true, "Supported previous version"),
                new BomSupportEntryResponse("CYCLONEDX", "XML", "1.5", "PREVIOUS", true, "Supported previous version"),
                new BomSupportEntryResponse("CYCLONEDX", "JSON", "1.4", "LEGACY", true, "Legacy support; validate correlations"),
                new BomSupportEntryResponse("CYCLONEDX", "XML", "1.4", "LEGACY", true, "Legacy support; validate correlations"),
                new BomSupportEntryResponse("SPDX", "JSON", "2.3", "CURRENT", true, "Preferred SPDX JSON support"),
                new BomSupportEntryResponse("SPDX", "JSON", "2.2", "PREVIOUS", true, "Supported previous version"),
                new BomSupportEntryResponse("SPDX", "JSON", "2.1", "LEGACY", true, "Legacy support; validate correlations"),
                new BomSupportEntryResponse("VENDOR", "JSON", "custom", "VENDOR_DEFINED", true, "Vendor-defined BOMs are accepted and normalized best-effort"),
                new BomSupportEntryResponse("VENDOR", "XML", "custom", "VENDOR_DEFINED", true, "Vendor-defined BOMs are accepted and normalized best-effort")
        ));
    }

    // ── XML support ──────────────────────────────────────────────────────────

    private boolean isXmlBytes(byte[] content) {
        if (content == null || content.length == 0) return false;
        int i = 0;
        while (i < content.length && (content[i] == 0x20 || content[i] == 0x09 || content[i] == 0x0A || content[i] == 0x0D)) {
            i++;
        }
        return i < content.length && content[i] == '<';
    }

    private SbomFormat detectFormatFromXml(byte[] content) {
        try {
            Document doc = buildXmlDocument(content);
            Element root = doc.getDocumentElement();
            String ns = root.getNamespaceURI();
            if ("bom".equals(root.getLocalName()) && ns != null && ns.startsWith("http://cyclonedx.org/schema/bom/")) {
                return SbomFormat.CYCLONEDX;
            }
            if (SpdxXmlConverter.isSpdxXml(root)) {
                return SbomFormat.SPDX;
            }
        } catch (Exception e) {
            // fall through
        }
        return SbomFormat.UNKNOWN;
    }

    /**
     * Returns the SPDX JSON-shaped tree for an SPDX XML document, or null when the content is not
     * SPDX XML (including CycloneDX XML and JSON), so callers can reuse the SPDX JSON extraction.
     */
    public JsonNode readSpdxXml(byte[] content) throws IOException {
        if (!isXmlBytes(content)) {
            return null;
        }
        try {
            Element root = buildXmlDocument(content).getDocumentElement();
            return SpdxXmlConverter.isSpdxXml(root) ? SpdxXmlConverter.toJson(root, objectMapper) : null;
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Failed to parse SPDX XML document", e);
        }
    }

    private String[] extractXmlVersion(byte[] content) {
        try {
            Document doc = buildXmlDocument(content);
            Element root = doc.getDocumentElement();
            if (SpdxXmlConverter.isSpdxXml(root)) {
                String spdxVersion = blankToNull(xmlChildText(root, "spdxVersion"));
                return new String[] {
                        blankToNull(xmlChildText(root, "documentNamespace")),
                        spdxVersion == null ? null : blankToNull(spdxVersion.replace("SPDX-", "").trim())
                };
            }
            String serial = blankToNull(root.getAttribute("serialNumber"));
            String version = blankToNull(root.getAttribute("version"));
            return new String[] { serial, version };
        } catch (Exception ignored) {
            return new String[] { null, null };
        }
    }

    List<ParsedComponent> parseXmlContent(byte[] content) throws IOException {
        List<ParsedComponent> result = new ArrayList<>();
        try {
            Document doc = buildXmlDocument(content);
            Element bom = doc.getDocumentElement();
            if (SpdxXmlConverter.isSpdxXml(bom)) {
                return parseSpdx(SpdxXmlConverter.toJson(bom, objectMapper));
            }
            Element componentsEl = xmlFindElement(bom, "components");
            if (componentsEl == null) {
                return result;
            }
            NodeList children = componentsEl.getChildNodes();
            int componentCount = 0;
            for (int i = 0; i < children.getLength(); i++) {
                Node node = children.item(i);
                if (node.getNodeType() != Node.ELEMENT_NODE) continue;
                if (!xmlLocalNameMatches((Element) node, "component")) continue;
                BomInputLimits.checkComponentCount(++componentCount);
                ParsedComponent parsed = parseXmlComponent((Element) node);
                if (parsed != null) {
                    result.add(parsed);
                }
            }
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Failed to parse XML BOM components", e);
        }
        return result;
    }

    private ParsedComponent parseXmlComponent(Element comp) {
        String name = xmlChildText(comp, "name");
        if (name == null || name.isBlank()) return null;

        String version = nullIfBlank(xmlChildText(comp, "version"));
        String purl = nullIfBlank(xmlChildText(comp, "purl"));
        String group = nullIfBlank(xmlChildText(comp, "group"));
        String scope = nullIfBlank(xmlChildText(comp, "scope"));

        // License
        String license = null;
        Element licensesEl = xmlFindElement(comp, "licenses");
        if (licensesEl != null) {
            Element licenseEl = xmlFindElement(licensesEl, "license");
            if (licenseEl != null) {
                license = nullIfBlank(xmlChildText(licenseEl, "id"));
                if (license == null) license = nullIfBlank(xmlChildText(licenseEl, "name"));
            }
        }

        // CPE
        String cpeRaw = nullIfBlank(xmlChildText(comp, "cpe"));
        List<String> cpes = new ArrayList<>();
        if (cpeRaw != null) {
            String normalized = CpeUtil.normalizeCpe23(cpeRaw);
            if (normalized != null) cpes.add(normalized);
        }

        // Hash (SHA-256 only)
        String digest = null;
        Element hashesEl = xmlFindElement(comp, "hashes");
        if (hashesEl != null) {
            NodeList hashNodes = hashesEl.getChildNodes();
            for (int i = 0; i < hashNodes.getLength() && digest == null; i++) {
                Node n = hashNodes.item(i);
                if (n.getNodeType() != Node.ELEMENT_NODE) continue;
                Element hashEl = (Element) n;
                if (!xmlLocalNameMatches(hashEl, "hash")) continue;
                digest = normalizeDigest(hashEl.getAttribute("alg"), BomInputLimits.xmlText(hashEl));
            }
        }

        String effectivePurl = purl != null ? purl : "";
        String effectiveName = name.trim().toLowerCase(Locale.ROOT);
        String effectiveVersion = version != null ? version : "0";

        PurlUtil.ParsedPurl parsed = PurlUtil.parse(effectivePurl);
        String ecosystem = "unknown".equals(parsed.ecosystem()) ? "generic" : parsed.ecosystem();
        String packageName = "unknown".equals(parsed.packageName()) ? effectiveName : parsed.packageName();
        String resolvedVersion = (parsed.version() == null || "0".equals(parsed.version())) ? effectiveVersion : parsed.version();
        String resolvedPurl = effectivePurl.isBlank()
                ? "pkg:" + ecosystem + "/" + packageName + "@" + resolvedVersion
                : effectivePurl;

        cpes = augmentCpesWithPurlDerivation(cpes, resolvedPurl, packageName);

        // CycloneDX XML carries the type as an attribute on <component type="...">.
        String componentType = nullIfBlank(comp.getAttribute("type"));
        return new ParsedComponent(ecosystem, packageName, resolvedVersion, resolvedPurl, digest, cpes, group, license, scope, componentType);
    }

    Document buildXmlDocument(byte[] content) throws Exception {
        BomInputLimits.checkBytes(content);
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        // These are mandatory security controls. If the parser cannot enforce
        // them, fail closed instead of accepting potentially hostile XML.
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setExpandEntityReferences(false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.setEntityResolver((publicId, systemId) -> {
            throw new SAXException("External entity resolution is disabled");
        });
        builder.setErrorHandler(null);
        return builder.parse(new ByteArrayInputStream(content));
    }

    /** Returns true if the element's local name matches (handles both namespace-aware and unaware). */
    private boolean xmlLocalNameMatches(Element el, String localName) {
        String local = el.getLocalName();
        if (local != null) return localName.equals(local);
        // Fallback for non-namespace-aware parsers: strip prefix from node name
        String nodeName = el.getNodeName();
        int colon = nodeName.lastIndexOf(':');
        return localName.equals(colon >= 0 ? nodeName.substring(colon + 1) : nodeName);
    }

    /** Returns the first direct child element with the given local name. */
    Element xmlFirstChild(Element parent, String localName) {
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node n = children.item(i);
            if (n.getNodeType() == Node.ELEMENT_NODE && xmlLocalNameMatches((Element) n, localName)) {
                return (Element) n;
            }
        }
        return null;
    }

    /**
     * Finds a descendant element by local name — tries direct child first, then
     * {@code getElementsByTagNameNS("*", ...)} as fallback for unusual namespace configs.
     */
    private Element xmlFindElement(Element parent, String localName) {
        Element direct = xmlFirstChild(parent, localName);
        if (direct != null) return direct;
        // Fallback: namespace-wildcard recursive search
        NodeList nl = parent.getElementsByTagNameNS("*", localName);
        if (nl.getLength() > 0) return (Element) nl.item(0);
        // Final fallback: no-namespace search
        NodeList nl2 = parent.getElementsByTagName(localName);
        if (nl2.getLength() > 0) return (Element) nl2.item(0);
        return null;
    }

    /** Returns text content of the first child element with the given local name, or null. */
    String xmlChildText(Element parent, String localName) {
        Element child = xmlFirstChild(parent, localName);
        if (child == null) {
            // Fallback: try namespace-wildcard search within direct subtree
            NodeList nl = parent.getElementsByTagNameNS("*", localName);
            if (nl.getLength() > 0) child = (Element) nl.item(0);
            else {
                NodeList nl2 = parent.getElementsByTagName(localName);
                if (nl2.getLength() > 0) child = (Element) nl2.item(0);
            }
        }
        if (child == null) return null;
        String text = BomInputLimits.xmlText(child);
        return (text == null || text.isBlank()) ? null : text.trim();
    }

    private List<ParsedComponent> parseCycloneDx(JsonNode root) throws IOException {
        BomInputLimits.checkComponentCount(root.path("components").size());
        List<ParsedComponent> components = new ArrayList<>();
        for (JsonNode component : root.path("components")) {
            String purl = component.path("purl").asText("");
            String name = component.path("name").asText("unknown");
            String version = component.path("version").asText("0");
            PurlUtil.ParsedPurl parsed = PurlUtil.parse(purl);
            String ecosystem = parsed.ecosystem();
            String packageName = parsed.packageName();
            String resolvedVersion = parsed.version() == null || parsed.version().equals("0") ? version : parsed.version();
            if (packageName.equals("unknown")) {
                packageName = name.toLowerCase();
            }
            if (ecosystem.equals("unknown")) {
                ecosystem = "generic";
            }
            String resolvedPurl = purl.isBlank()
                    ? "pkg:" + ecosystem + "/" + packageName + "@" + resolvedVersion
                    : purl;
            String digest = firstNonBlank(
                    extractDigestFromCycloneDxComponent(component),
                    extractDigestFromPurl(resolvedPurl),
                    extractDigestFromBomRef(component.path("bom-ref").asText(""))
            );
            List<String> cpes = augmentCpesWithPurlDerivation(
                    extractCpesFromCycloneDxComponent(component),
                    resolvedPurl,
                    packageName
            );
            String group = nullIfBlank(component.path("group").asText(null));
            String license = extractLicenseFromCycloneDx(component);
            String scope = nullIfBlank(component.path("scope").asText(null));
            String componentType = nullIfBlank(component.path("type").asText(null));
            components.add(new ParsedComponent(
                    ecosystem,
                    packageName,
                    resolvedVersion,
                    resolvedPurl,
                    digest,
                    cpes,
                    group,
                    license,
                    scope,
                    componentType
            ));
        }
        return components;
    }

    private List<ParsedComponent> parseSpdx(JsonNode root) throws IOException {
        BomInputLimits.checkComponentCount(root.path("packages").size());
        List<ParsedComponent> components = new ArrayList<>();
        for (JsonNode pkg : root.path("packages")) {
            String name = pkg.path("name").asText("unknown").toLowerCase();
            String version = pkg.path("versionInfo").asText("0");
            String purl = extractPurlFromSpdx(pkg);
            PurlUtil.ParsedPurl parsed = PurlUtil.parse(purl);
            String ecosystem = parsed.ecosystem();
            String packageName = parsed.packageName();
            if (packageName.equals("unknown")) {
                packageName = name;
            }
            if (ecosystem.equals("unknown")) {
                ecosystem = "generic";
            }
            String resolvedPurl = purl.isBlank()
                    ? "pkg:" + ecosystem + "/" + packageName + "@" + version
                    : purl;
            String digest = firstNonBlank(
                    extractDigestFromSpdxPackage(pkg),
                    extractDigestFromPurl(resolvedPurl)
            );
            List<String> cpes = augmentCpesWithPurlDerivation(
                    extractCpesFromSpdxPackage(pkg),
                    resolvedPurl,
                    packageName
            );
            String spdxLicense = nullIfBlank(pkg.path("licenseDeclared").asText(null));
            components.add(new ParsedComponent(
                    ecosystem,
                    packageName,
                    version,
                    resolvedPurl,
                    digest,
                    cpes,
                    null,
                    spdxLicense,
                    null,
                    // SPDX has no component-type equivalent; an SPDX package is software.
                    "library"
            ));
        }
        return components;
    }

    private String extractFormatVersion(JsonNode root, SbomFormat format) {
        if (format == SbomFormat.CYCLONEDX) {
            return blankToNull(root.path("specVersion").asText(null));
        }
        if (format == SbomFormat.SPDX) {
            String value = root.path("spdxVersion").asText(null);
            return value == null ? null : blankToNull(value.replace("SPDX-", "").trim());
        }
        return null;
    }

    private String evaluateSupportLevel(String version, List<String> current, List<String> previous, List<String> legacy) {
        String normalized = blankToNull(version);
        if (normalized == null) {
            return "UNKNOWN";
        }
        if (current.contains(normalized)) {
            return "CURRENT";
        }
        if (previous.contains(normalized)) {
            return "PREVIOUS";
        }
        if (legacy.contains(normalized)) {
            return "LEGACY";
        }
        return "UNKNOWN";
    }

    private String blankToNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }

    private List<String> augmentCpesWithPurlDerivation(List<String> explicitCpes, String purl, String fallbackPackageName) {
        Set<String> cpes = new LinkedHashSet<>();
        if (explicitCpes != null) {
            cpes.addAll(explicitCpes);
        }
        maybeAddCpe(cpes, deriveCpeFromPurl(purl, fallbackPackageName));
        return new ArrayList<>(cpes);
    }

    private String extractPurlFromSpdx(JsonNode pkg) {
        for (JsonNode ref : pkg.path("externalRefs")) {
            String type = ref.path("referenceType").asText("");
            if ("purl".equalsIgnoreCase(type) || "PACKAGE-MANAGER".equalsIgnoreCase(type)) {
                String locator = ref.path("referenceLocator").asText("");
                if (locator.startsWith("pkg:")) {
                    return locator;
                }
            }
        }
        return "";
    }

    private List<String> extractCpesFromCycloneDxComponent(JsonNode component) {
        Set<String> cpes = new LinkedHashSet<>();
        maybeAddCpe(cpes, component.path("cpe").asText(""));
        maybeAddCpe(cpes, component.path("bom-ref").asText(""));

        JsonNode properties = component.path("properties");
        if (properties.isArray()) {
            for (JsonNode property : properties) {
                String name = property.path("name").asText("");
                if (name == null || name.isBlank()) {
                    continue;
                }
                String normalizedName = name.trim().toLowerCase(Locale.ROOT);
                if (!normalizedName.contains("cpe")) {
                    continue;
                }
                maybeAddCpe(cpes, property.path("value").asText(""));
            }
        }
        return new ArrayList<>(cpes);
    }

    private List<String> extractCpesFromSpdxPackage(JsonNode pkg) {
        Set<String> cpes = new LinkedHashSet<>();
        JsonNode refs = pkg.path("externalRefs");
        if (!refs.isArray()) {
            return List.of();
        }
        for (JsonNode ref : refs) {
            String type = ref.path("referenceType").asText("");
            if (type == null || type.isBlank()) {
                continue;
            }
            String normalizedType = type.trim().toLowerCase(Locale.ROOT);
            if (!normalizedType.contains("cpe")) {
                continue;
            }
            maybeAddCpe(cpes, ref.path("referenceLocator").asText(""));
        }
        return new ArrayList<>(cpes);
    }

    private void maybeAddCpe(Set<String> cpes, String rawCpe) {
        String normalized = CpeUtil.normalizeCpe23(rawCpe);
        if (normalized != null) {
            cpes.add(normalized);
        }
    }

    private String deriveCpeFromPurl(String purl, String fallbackPackageName) {
        PurlUtil.ParsedPurl parsed = PurlUtil.parse(purl);
        String ecosystem = parsed.ecosystem() == null ? "" : parsed.ecosystem().trim().toLowerCase(Locale.ROOT);
        if (ecosystem.isBlank() || "unknown".equals(ecosystem)) {
            return null;
        }

        String product = sanitizeCpeToken(parsed.packageName());
        if (!hasText(product) || "unknown".equals(product)) {
            product = sanitizeCpeToken(fallbackPackageName);
        }
        if (!hasText(product) || "unknown".equals(product)) {
            return null;
        }

        String vendor = sanitizeCpeToken(parsed.namespace());
        if (!hasText(vendor) || "unknown".equals(vendor)) {
            vendor = product;
        }

        return "cpe:2.3:a:" + vendor + ":" + product + ":*:*:*:*:*:*:*:*";
    }

    private String sanitizeCpeToken(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String normalized = value.trim()
                .toLowerCase(Locale.ROOT)
                .replace(" ", "_")
                .replaceAll("[^a-z0-9._-]", "_");
        return normalized.isBlank() ? null : normalized;
    }

    private JsonNode normalizeRoot(JsonNode root) throws IOException {
        if (root == null || !root.isObject()) {
            throw new IOException("BOM must be a JSON object");
        }
        JsonNode nestedSbom = root.path("sbom");
        if (nestedSbom.isObject()) {
            return nestedSbom;
        }
        return root;
    }

    private String extractDigestFromCycloneDxComponent(JsonNode component) {
        JsonNode hashes = component.path("hashes");
        if (!hashes.isArray()) {
            return null;
        }
        for (JsonNode hash : hashes) {
            String algorithm = hash.path("alg").asText("");
            String content = hash.path("content").asText("");
            String normalized = normalizeDigest(algorithm, content);
            if (normalized != null) {
                return normalized;
            }
        }
        return null;
    }

    private String extractDigestFromSpdxPackage(JsonNode pkg) {
        JsonNode checksums = pkg.path("checksums");
        if (!checksums.isArray()) {
            return null;
        }
        for (JsonNode checksum : checksums) {
            String algorithm = checksum.path("algorithm").asText("");
            String value = checksum.path("checksumValue").asText("");
            String normalized = normalizeDigest(algorithm, value);
            if (normalized != null) {
                return normalized;
            }
        }
        return null;
    }

    private String extractDigestFromPurl(String purl) {
        if (purl == null || purl.isBlank()) {
            return null;
        }
        int queryStart = purl.indexOf('?');
        if (queryStart < 0 || queryStart + 1 >= purl.length()) {
            return null;
        }
        String query = purl.substring(queryStart + 1);
        int fragment = query.indexOf('#');
        if (fragment >= 0) {
            query = query.substring(0, fragment);
        }
        for (String token : query.split("&")) {
            int equals = token.indexOf('=');
            if (equals <= 0 || equals + 1 >= token.length()) {
                continue;
            }
            String key = token.substring(0, equals).toLowerCase(Locale.ROOT);
            String value = token.substring(equals + 1);
            if ("checksum".equals(key) || "digest".equals(key)) {
                String normalized = normalizeDigestToken(value);
                if (normalized != null) {
                    return normalized;
                }
            }
        }
        return null;
    }

    private String extractDigestFromBomRef(String bomRef) {
        if (bomRef == null || bomRef.isBlank()) {
            return null;
        }
        String candidate = bomRef.trim().toLowerCase(Locale.ROOT);
        int idx = candidate.indexOf("sha256:");
        if (idx < 0) {
            return null;
        }
        return normalizeDigestToken(candidate.substring(idx));
    }

    private String normalizeDigest(String algorithm, String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String alg = algorithm == null ? "" : algorithm.trim().toLowerCase(Locale.ROOT).replace("-", "");
        String digestValue = value.trim().toLowerCase(Locale.ROOT);
        if (digestValue.contains(":")) {
            return normalizeDigestToken(digestValue);
        }
        if ("sha256".equals(alg)) {
            return normalizeDigestToken("sha256:" + digestValue);
        }
        return null;
    }

    private String normalizeDigestToken(String token) {
        if (token == null || token.isBlank()) {
            return null;
        }
        String normalized = token.trim().toLowerCase(Locale.ROOT);
        if (!normalized.startsWith("sha256:")) {
            if (normalized.startsWith("sha-256:")) {
                normalized = "sha256:" + normalized.substring("sha-256:".length());
            } else {
                return null;
            }
        }
        String digestValue = normalized.substring("sha256:".length()).trim();
        if (digestValue.length() != 64) {
            return null;
        }
        for (int i = 0; i < digestValue.length(); i++) {
            char ch = digestValue.charAt(i);
            boolean hex = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
            if (!hex) {
                return null;
            }
        }
        return "sha256:" + digestValue;
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return null;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private String nullIfBlank(String value) {
        return (value == null || value.isBlank()) ? null : value.trim();
    }

    private String extractLicenseFromCycloneDx(JsonNode component) {
        JsonNode licenses = component.path("licenses");
        if (!licenses.isArray() || licenses.isEmpty()) {
            return null;
        }
        List<String> ids = new ArrayList<>();
        for (JsonNode entry : licenses) {
            JsonNode lic = entry.path("license");
            String id = nullIfBlank(lic.path("id").asText(null));
            if (id == null) id = nullIfBlank(lic.path("name").asText(null));
            if (id != null) ids.add(id);
        }
        return ids.isEmpty() ? null : String.join(" | ", ids);
    }
}
