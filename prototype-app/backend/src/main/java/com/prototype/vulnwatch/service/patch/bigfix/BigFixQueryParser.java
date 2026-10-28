package com.prototype.vulnwatch.service.patch.bigfix;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

/**
 * Streams the BESAPI XML returned by {@code /api/query} into rows of answers.
 *
 * <p>The parser refuses DTDs and external entities, so a hostile or compromised server cannot use
 * XML entity tricks to read files or reach other hosts. A single-answer result becomes a one-column
 * row; a tuple becomes one column per answer.
 */
final class BigFixQueryParser {

    record Rows(List<List<String>> rows, boolean truncated) {}

    static class QueryFailedException extends RuntimeException {
        QueryFailedException(String message) {
            super(message);
        }
    }

    private BigFixQueryParser() { }

    static Rows parse(String xml, int maxRows) {
        XMLInputFactory factory = XMLInputFactory.newFactory();
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, false);
        trySet(factory, XMLConstants.ACCESS_EXTERNAL_DTD, "");
        trySet(factory, XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");

        List<List<String>> rows = new ArrayList<>();
        boolean truncated = false;
        List<String> tuple = null;
        int depthInResult = 0;
        boolean inResult = false;
        try {
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xml == null ? "" : xml));
            try {
                while (reader.hasNext()) {
                    int event = reader.next();
                    if (event == XMLStreamConstants.DTD) {
                        throw new QueryFailedException("BigFix response contained a DTD");
                    }
                    if (event == XMLStreamConstants.START_ELEMENT) {
                        String name = reader.getLocalName();
                        if ("Result".equals(name)) {
                            inResult = true;
                        } else if ("Error".equals(name)) {
                            String message = reader.getElementText();
                            throw new QueryFailedException("BigFix relevance error: " + limit(message, 300));
                        } else if (inResult && "Tuple".equals(name)) {
                            if (tuple == null) tuple = new ArrayList<>();
                            depthInResult++;
                        } else if (inResult && "Answer".equals(name)) {
                            String answer = reader.getElementText();
                            if (tuple != null) {
                                tuple.add(answer);
                            } else if (rows.size() < maxRows) {
                                rows.add(List.of(answer));
                            } else {
                                truncated = true;
                            }
                        }
                    } else if (event == XMLStreamConstants.END_ELEMENT) {
                        String name = reader.getLocalName();
                        if ("Tuple".equals(name) && tuple != null) {
                            depthInResult--;
                            // Nested tuples flatten into the enclosing row.
                            if (depthInResult == 0) {
                                if (rows.size() < maxRows) rows.add(List.copyOf(tuple));
                                else truncated = true;
                                tuple = null;
                            }
                        } else if ("Result".equals(name)) {
                            inResult = false;
                        }
                    }
                }
            } finally {
                reader.close();
            }
        } catch (XMLStreamException malformed) {
            throw new QueryFailedException("BigFix returned malformed XML");
        }
        return new Rows(rows, truncated);
    }

    private static void trySet(XMLInputFactory factory, String property, Object value) {
        try {
            factory.setProperty(property, value);
        } catch (IllegalArgumentException unsupported) {
            // Not every StAX implementation recognises the JAXP access properties; DTDs are already off.
        }
    }

    private static String limit(String value, int max) {
        return value == null || value.length() <= max ? value : value.substring(0, max);
    }
}
