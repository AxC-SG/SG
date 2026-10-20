package com.prototype.vulnwatch.service.cbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.CbomAssetType;
import com.prototype.vulnwatch.util.BomInputLimits;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

@Service
public class CbomComponentParser {

    private final ObjectMapper objectMapper;

    public CbomComponentParser(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public List<CbomParsedComponent> parse(byte[] content) throws IOException {
        BomInputLimits.checkBytes(content);
        if (looksLikeXml(content)) {
            return parseXml(content);
        }
        return parseJson(content);
    }

    private List<CbomParsedComponent> parseJson(byte[] content) throws IOException {
        JsonNode root = objectMapper.readTree(content);
        if (root == null || !root.isObject()) {
            throw new IOException("BOM must be a JSON object");
        }
        JsonNode nested = root.path("cbom");
        if (nested.isObject()) {
            root = nested;
        } else if (root.path("sbom").isObject()) {
            root = root.path("sbom");
        }
        JsonNode components = root.path("components");
        if (!components.isArray()) {
            return List.of();
        }
        BomInputLimits.checkComponentCount(components.size());
        List<CbomParsedComponent> result = new ArrayList<>();
        for (JsonNode component : components) {
            String type = text(component, "type");
            JsonNode crypto = component.path("cryptoProperties");
            if (!"cryptographic-asset".equalsIgnoreCase(nullToBlank(type)) && crypto.isMissingNode()) {
                continue;
            }
            String name = text(component, "name");
            if (isBlank(name)) {
                continue;
            }
            Map<String, String> props = readProperties(component.path("properties"));
            JsonNode algorithm = crypto.path("algorithmProperties");
            JsonNode material = crypto.path("relatedCryptoMaterialProperties");
            JsonNode protocol = crypto.path("protocolProperties");
            JsonNode certificate = crypto.path("certificateProperties");
            String bomRef = text(component, "bom-ref");
            CbomAssetType assetType = parseAssetType(text(crypto, "assetType"));
            String primitive = firstText(algorithm, "primitive", "algorithm", "cryptoAlgorithm");
            String componentType = firstNonBlank(
                    firstText(material, "type", "assetType", "cryptoMaterialType"),
                    props.get("componentType"),
                    props.get("materialType")
            );
            CbomParsedComponent parsed = new CbomParsedComponent(
                    blankToNull(bomRef),
                    fingerprint(bomRef, name, assetType, primitive, componentType, text(component, "description")),
                    name.trim(),
                    blankToNull(text(component, "description")),
                    assetType,
                    blankToNull(componentType),
                    blankToNull(primitive),
                    blankToNull(firstText(algorithm, "parameterSetIdentifier", "parameterSet")),
                    firstInt(algorithm, "keySize", "keyLength", "parameterSize"),
                    blankToNull(firstText(algorithm, "curve", "namedCurve")),
                    blankToNull(firstText(algorithm, "padding", "paddingScheme")),
                    blankToNull(firstText(protocol, "version", "protocolVersion")),
                    blankToNull(firstText(material, "state", "materialState")),
                    blankToNull(firstText(material, "format", "encoding")),
                    blankToNull(firstNonBlank(props.get("storageLocation"), props.get("storage"), props.get("location"))),
                    blankToNull(firstNonBlank(props.get("transmission"), props.get("transmitted"))),
                    blankToNull(firstNonBlank(props.get("sensitivity"), props.get("classification"))),
                    blankToNull(firstNonBlank(props.get("usedIn"), props.get("usage"), props.get("context"))),
                    parseDate(firstText(certificate, "notBefore", "validFrom")),
                    parseDate(firstText(certificate, "notAfter", "validUntil", "expires")),
                    blankToNull(firstText(certificate, "issuer")),
                    blankToNull(firstText(certificate, "subject")),
                    blankToNull(firstText(certificate, "serialNumber")),
                    blankToNull(firstText(certificate, "signatureAlgorithm")),
                    blankToNull(firstText(certificate, "keyUsage"))
            );
            result.add(parsed);
        }
        return result;
    }

    private List<CbomParsedComponent> parseXml(byte[] content) throws IOException {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            Document doc = factory.newDocumentBuilder().parse(new ByteArrayInputStream(content));
            Element root = doc.getDocumentElement();
            Element components = firstChild(root, "components");
            if (components == null) {
                return List.of();
            }
            List<CbomParsedComponent> result = new ArrayList<>();
            NodeList children = components.getChildNodes();
            int componentCount = 0;
            for (int i = 0; i < children.getLength(); i++) {
                if (children.item(i).getNodeType() != Node.ELEMENT_NODE) {
                    continue;
                }
                Element component = (Element) children.item(i);
                if (!"component".equals(localName(component))) {
                    continue;
                }
                BomInputLimits.checkComponentCount(++componentCount);
                Element crypto = firstChild(component, "cryptoProperties");
                String type = blankToNull(component.getAttribute("type"));
                if (!"cryptographic-asset".equalsIgnoreCase(nullToBlank(type)) && crypto == null) {
                    continue;
                }
                String name = childText(component, "name");
                if (isBlank(name)) {
                    continue;
                }
                Map<String, String> props = readXmlProperties(firstChild(component, "properties"));
                Element algorithm = firstChild(crypto, "algorithmProperties");
                Element material = firstChild(crypto, "relatedCryptoMaterialProperties");
                Element protocol = firstChild(crypto, "protocolProperties");
                Element certificate = firstChild(crypto, "certificateProperties");
                String bomRef = blankToNull(component.getAttribute("bom-ref"));
                CbomAssetType assetType = parseAssetType(childText(crypto, "assetType"));
                String primitive = firstNonBlank(childText(algorithm, "primitive"), childText(algorithm, "algorithm"));
                String componentType = firstNonBlank(
                        childText(material, "type"),
                        childText(material, "cryptoMaterialType"),
                        props.get("componentType"),
                        props.get("materialType")
                );
                result.add(new CbomParsedComponent(
                        bomRef,
                        fingerprint(bomRef, name, assetType, primitive, componentType, childText(component, "description")),
                        name.trim(),
                        blankToNull(childText(component, "description")),
                        assetType,
                        blankToNull(componentType),
                        blankToNull(primitive),
                        blankToNull(firstNonBlank(childText(algorithm, "parameterSetIdentifier"), childText(algorithm, "parameterSet"))),
                        firstInt(algorithm, "keySize", "keyLength", "parameterSize"),
                        blankToNull(firstNonBlank(childText(algorithm, "curve"), childText(algorithm, "namedCurve"))),
                        blankToNull(firstNonBlank(childText(algorithm, "padding"), childText(algorithm, "paddingScheme"))),
                        blankToNull(firstNonBlank(childText(protocol, "version"), childText(protocol, "protocolVersion"))),
                        blankToNull(firstNonBlank(childText(material, "state"), childText(material, "materialState"))),
                        blankToNull(firstNonBlank(childText(material, "format"), childText(material, "encoding"))),
                        blankToNull(firstNonBlank(props.get("storageLocation"), props.get("storage"), props.get("location"))),
                        blankToNull(firstNonBlank(props.get("transmission"), props.get("transmitted"))),
                        blankToNull(firstNonBlank(props.get("sensitivity"), props.get("classification"))),
                        blankToNull(firstNonBlank(props.get("usedIn"), props.get("usage"), props.get("context"))),
                        parseDate(firstNonBlank(childText(certificate, "notBefore"), childText(certificate, "validFrom"))),
                        parseDate(firstNonBlank(childText(certificate, "notAfter"), childText(certificate, "validUntil"), childText(certificate, "expires"))),
                        blankToNull(childText(certificate, "issuer")),
                        blankToNull(childText(certificate, "subject")),
                        blankToNull(childText(certificate, "serialNumber")),
                        blankToNull(childText(certificate, "signatureAlgorithm")),
                        blankToNull(childText(certificate, "keyUsage"))
                ));
            }
            return result;
        } catch (Exception e) {
            throw new IOException("Failed to parse CycloneDX CBOM XML", e);
        }
    }

    private Map<String, String> readProperties(JsonNode properties) {
        Map<String, String> result = new TreeMap<>();
        if (!properties.isArray()) {
            return result;
        }
        for (JsonNode property : properties) {
            String name = text(property, "name");
            String value = text(property, "value");
            addProperty(result, name, value);
        }
        return result;
    }

    private Map<String, String> readXmlProperties(Element properties) {
        Map<String, String> result = new TreeMap<>();
        if (properties == null) {
            return result;
        }
        NodeList children = properties.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            if (children.item(i).getNodeType() != Node.ELEMENT_NODE) continue;
            Element property = (Element) children.item(i);
            addProperty(result, property.getAttribute("name"), property.getAttribute("value"));
        }
        return result;
    }

    private void addProperty(Map<String, String> result, String name, String value) {
        if (isBlank(name) || isBlank(value)) {
            return;
        }
        String key = name.trim();
        int lastColon = key.lastIndexOf(':');
        if (lastColon >= 0 && lastColon < key.length() - 1) {
            key = key.substring(lastColon + 1);
        }
        result.put(key, value.trim());
    }

    private CbomAssetType parseAssetType(String raw) {
        String value = nullToBlank(raw).trim().toLowerCase(Locale.ROOT).replace('-', '_');
        return switch (value) {
            case "algorithm" -> CbomAssetType.ALGORITHM;
            case "certificate" -> CbomAssetType.CERTIFICATE;
            case "protocol" -> CbomAssetType.PROTOCOL;
            case "related_crypto_material", "relatedcryptomaterial", "crypto_material", "cryptographic_material" ->
                    CbomAssetType.RELATED_CRYPTO_MATERIAL;
            default -> CbomAssetType.UNKNOWN;
        };
    }

    private String fingerprint(String bomRef, String name, CbomAssetType assetType, String primitive, String componentType, String description) {
        String basis = firstNonBlank(bomRef, name + "|" + assetType + "|" + primitive + "|" + componentType + "|" + description);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(basis.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder("sha256:");
            for (byte b : hash) builder.append(String.format("%02x", b));
            return builder.toString();
        } catch (Exception e) {
            return "raw:" + basis;
        }
    }

    private boolean looksLikeXml(byte[] content) {
        String prefix = new String(content, 0, Math.min(content.length, 100), StandardCharsets.UTF_8).trim();
        return prefix.startsWith("<");
    }

    private String text(JsonNode node, String field) {
        if (node == null || node.isMissingNode() || node.isNull()) return null;
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText(null);
    }

    private String firstText(JsonNode node, String... fields) {
        for (String field : fields) {
            String value = text(node, field);
            if (!isBlank(value)) return value;
        }
        return null;
    }

    private Integer firstInt(JsonNode node, String... fields) {
        for (String field : fields) {
            JsonNode value = node == null ? null : node.get(field);
            if (value != null && value.isNumber()) return value.asInt();
            if (value != null && value.isTextual()) {
                try {
                    return Integer.parseInt(value.asText().trim());
                } catch (NumberFormatException ignored) {
                }
            }
        }
        return null;
    }

    private Integer firstInt(Element element, String... fields) {
        for (String field : fields) {
            String value = childText(element, field);
            if (!isBlank(value)) {
                try {
                    return Integer.parseInt(value.trim());
                } catch (NumberFormatException ignored) {
                }
            }
        }
        return null;
    }

    private LocalDate parseDate(String raw) {
        if (isBlank(raw)) return null;
        try {
            return LocalDate.parse(raw.trim());
        } catch (DateTimeParseException ignored) {
        }
        try {
            return OffsetDateTime.parse(raw.trim()).toLocalDate();
        } catch (DateTimeParseException ignored) {
        }
        return null;
    }

    private Element firstChild(Element parent, String name) {
        if (parent == null) return null;
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node node = children.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE && name.equals(localName(node))) {
                return (Element) node;
            }
        }
        return null;
    }

    private String childText(Element parent, String name) {
        Element child = firstChild(parent, name);
        return child == null ? null : BomInputLimits.xmlText(child);
    }

    private String localName(Node node) {
        String local = node.getLocalName();
        if (local != null) return local;
        String raw = node.getNodeName();
        int colon = raw.lastIndexOf(':');
        return colon >= 0 ? raw.substring(colon + 1) : raw;
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (!isBlank(value)) return value.trim();
        }
        return null;
    }

    private String blankToNull(String value) {
        return isBlank(value) ? null : value.trim();
    }

    private String nullToBlank(String value) {
        return value == null ? "" : value;
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
