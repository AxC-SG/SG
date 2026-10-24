package com.prototype.vulnwatch.service;

import java.util.UUID;

/** Explicit scope for normalization and publication; never inherited by executor threads. */
public final class IntelligenceWriteContext {
    private static final ThreadLocal<UUID> RUN = new ThreadLocal<>();
    private static final ThreadLocal<String> RECORD=new ThreadLocal<>();
    public static String sourceRecord() { return RECORD.get(); }
    public static void sourceRecord(String value) { RECORD.set(value); }
    private static final ThreadLocal<Boolean> PUBLISHING = new ThreadLocal<>();
    private IntelligenceWriteContext() { }
    public static UUID runId() { return RUN.get(); }
    public static boolean publishing() { return Boolean.TRUE.equals(PUBLISHING.get()); }
    public static void beginRun(UUID id) { RUN.set(id); }
    public static void endRun(UUID id) { if (id.equals(RUN.get())) { RUN.remove(); RECORD.remove(); } }
    public static Scope publication() {
        if (publishing()) throw new IllegalStateException("Nested intelligence publication");
        PUBLISHING.set(true);
        return () -> PUBLISHING.remove();
    }
    public interface Scope extends AutoCloseable { @Override void close(); }
}
