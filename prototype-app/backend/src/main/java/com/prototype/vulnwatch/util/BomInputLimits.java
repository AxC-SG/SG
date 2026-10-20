package com.prototype.vulnwatch.util;

import java.io.IOException;
import org.w3c.dom.Node;

/** The existing BOM ceilings, shared by every retained input representation. */
public final class BomInputLimits {
    public static final long MAX_BOM_BYTES = 50L * 1024 * 1024;
    public static final int MAX_COMPONENTS = 100_000;

    private BomInputLimits() {
    }

    public static void checkBytes(byte[] content) throws IOException {
        if (content == null || content.length == 0) {
            throw new IOException("BOM payload is empty");
        }
        if (content.length > MAX_BOM_BYTES) {
            throw new IOException("BOM payload is too large (max 50 MiB)");
        }
    }

    public static void checkComponentCount(int count) throws IOException {
        if (count > MAX_COMPONENTS) {
            throw new IOException("BOM exceeds max allowed component count (100000)");
        }
    }

    /** DOM's recursive getTextContent can exhaust the Java stack on deeply nested input. */
    public static String xmlText(Node root) {
        StringBuilder text = new StringBuilder();
        Node current = root.getFirstChild();
        while (current != null) {
            if (current.getNodeType() == Node.TEXT_NODE || current.getNodeType() == Node.CDATA_SECTION_NODE) {
                text.append(current.getNodeValue());
            }
            if (current.getFirstChild() != null) {
                current = current.getFirstChild();
                continue;
            }
            while (current != root && current.getNextSibling() == null) {
                current = current.getParentNode();
            }
            current = current == root ? null : current.getNextSibling();
        }
        return text.toString();
    }
}
