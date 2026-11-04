package com.prototype.vulnwatch.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.util.Set;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Maps an SPDX 2.x XML document onto the tree an SPDX JSON document would have produced, so the
 * existing SPDX JSON extraction handles both serializations identically.
 *
 * <p>SPDX XML has no namespace of its own: the root is {@code <Document>} and its first marker is an
 * {@code <spdxVersion>} child starting with {@code SPDX-}. An array is serialized as a repeated
 * element, so an array with one entry is indistinguishable from an object; the fields below are
 * always arrays in the SPDX model and are forced to arrays even when they occur once.
 */
public final class SpdxXmlConverter {

    private static final int MAX_DEPTH = 32;

    private static final Set<String> ARRAY_FIELDS = Set.of(
            "packages", "files", "snippets", "relationships", "annotations", "externalRefs",
            "checksums", "hasExtractedLicenseInfos", "externalDocumentRefs", "licenseInfoFromFiles",
            "licenseInfoInFiles", "creators", "seeAlsos", "fileTypes", "fileContributors",
            "hasFiles", "attributionTexts", "ranges", "licenseInfoInSnippets", "snippetFromFile");

    private SpdxXmlConverter() {
    }

    public static boolean isSpdxXml(Element root) {
        if (root == null || !"Document".equals(localName(root))) {
            return false;
        }
        Element version = firstChild(root, "spdxVersion");
        return version != null && text(version).startsWith("SPDX-");
    }

    public static JsonNode toJson(Element root, ObjectMapper mapper) throws IOException {
        return convert(root, mapper, 0);
    }

    private static JsonNode convert(Element element, ObjectMapper mapper, int depth) throws IOException {
        if (depth > MAX_DEPTH) {
            throw new IOException("SPDX XML document is nested too deeply");
        }
        if (!hasElementChildren(element)) {
            return mapper.getNodeFactory().textNode(text(element));
        }
        ObjectNode object = mapper.createObjectNode();
        NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node node = children.item(i);
            if (node.getNodeType() != Node.ELEMENT_NODE) {
                continue;
            }
            Element child = (Element) node;
            String key = localName(child);
            JsonNode value = convert(child, mapper, depth + 1);
            JsonNode existing = object.get(key);
            if (existing == null) {
                if (ARRAY_FIELDS.contains(key)) {
                    object.set(key, mapper.createArrayNode().add(value));
                } else {
                    object.set(key, value);
                }
            } else if (existing.isArray()) {
                ((ArrayNode) existing).add(value);
            } else {
                object.set(key, mapper.createArrayNode().add(existing).add(value));
            }
        }
        return object;
    }

    private static boolean hasElementChildren(Element element) {
        NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            if (children.item(i).getNodeType() == Node.ELEMENT_NODE) {
                return true;
            }
        }
        return false;
    }

    private static Element firstChild(Element parent, String name) {
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node node = children.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE && name.equals(localName((Element) node))) {
                return (Element) node;
            }
        }
        return null;
    }

    private static String text(Element element) {
        String value = element.getTextContent();
        return value == null ? "" : value.trim();
    }

    private static String localName(Element element) {
        String local = element.getLocalName();
        if (local != null) {
            return local;
        }
        String name = element.getNodeName();
        int colon = name.lastIndexOf(':');
        return colon >= 0 ? name.substring(colon + 1) : name;
    }
}
