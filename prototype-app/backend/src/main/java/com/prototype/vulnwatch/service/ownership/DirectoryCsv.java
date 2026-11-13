package com.prototype.vulnwatch.service.ownership;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Strict, bounded RFC 4180 reader for directory import templates (plan §6.3, §10.4). Rejects non-UTF-8 input,
 * archives, unterminated quotes and over-limit files before any row is interpreted.
 */
final class DirectoryCsv {

    static final int MAX_BYTES = 5 * 1024 * 1024;
    static final int MAX_ROWS = 50_000;
    static final int MAX_FIELD = 1_000;

    static final class CsvRejected extends RuntimeException {
        CsvRejected(String message) {
            super(message);
        }
    }

    private DirectoryCsv() { }

    /** Returns all records including the header row. */
    static List<List<String>> parse(byte[] bytes) {
        if (bytes == null || bytes.length == 0) throw new CsvRejected("The file is empty");
        if (bytes.length > MAX_BYTES) throw new CsvRejected("Files are limited to " + MAX_BYTES / (1024 * 1024) + " MB");
        if (bytes.length >= 4 && bytes[0] == 'P' && bytes[1] == 'K' && bytes[2] == 3 && bytes[3] == 4) {
            throw new CsvRejected("Archives are not accepted; upload a plain CSV file");
        }
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException ex) {
            throw new CsvRejected("The file must be UTF-8 encoded");
        }
        if (text.startsWith("﻿")) text = text.substring(1);
        if (text.indexOf('\0') >= 0) throw new CsvRejected("The file contains binary data");

        List<List<String>> records = new ArrayList<>();
        List<String> record = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        boolean quoted = false;
        boolean fieldStarted = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (quoted) {
                if (c == '"') {
                    if (i + 1 < text.length() && text.charAt(i + 1) == '"') {
                        field.append('"');
                        i++;
                    } else {
                        quoted = false;
                    }
                } else {
                    field.append(c);
                }
            } else if (c == '"' && !fieldStarted) {
                quoted = true;
                fieldStarted = true;
            } else if (c == ',') {
                endField(record, field);
                fieldStarted = false;
            } else if (c == '\r' || c == '\n') {
                if (c == '\r' && i + 1 < text.length() && text.charAt(i + 1) == '\n') i++;
                endField(record, field);
                fieldStarted = false;
                endRecord(records, record);
                record = new ArrayList<>();
            } else if (c == '"') {
                throw new CsvRejected("Row " + (records.size() + 1) + ": quotes must enclose the whole field");
            } else {
                field.append(c);
                fieldStarted = true;
            }
            if (field.length() > MAX_FIELD) throw new CsvRejected("Row " + (records.size() + 1) + ": a field exceeds " + MAX_FIELD + " characters");
        }
        if (quoted) throw new CsvRejected("The file ends inside a quoted field");
        if (fieldStarted || !record.isEmpty() || field.length() > 0) {
            endField(record, field);
            endRecord(records, record);
        }
        if (records.isEmpty()) throw new CsvRejected("The file has no header row");
        return records;
    }

    private static void endField(List<String> record, StringBuilder field) {
        record.add(field.toString());
        field.setLength(0);
    }

    private static void endRecord(List<List<String>> records, List<String> record) {
        if (record.size() == 1 && record.get(0).isEmpty()) return; // blank line
        if (records.size() > MAX_ROWS) throw new CsvRejected("Files are limited to " + MAX_ROWS + " rows");
        records.add(record);
    }

    /** Spreadsheet formula prefixes (plan §6.3); such cells are rejected on import and escaped on export. */
    static boolean looksLikeFormula(String value) {
        if (value == null || value.isEmpty()) return false;
        char c = value.charAt(0);
        return c == '=' || c == '+' || c == '-' || c == '@' || c == '\t' || c == '\r';
    }

    /** Export-side escaping: prefix formula-looking values with a single quote. */
    static String escapeForExport(String value) {
        return looksLikeFormula(value) ? "'" + value : value;
    }
}
