package com.prototype.vulnwatch.service;

import java.util.Locale;
import java.util.Set;

/** Connector names, normalized evidence and tenant preferences share this registry. */
public final class IntelligenceSourceRegistry {
    public static final Set<String> SOURCES=Set.of("nvd","kev","ghsa","redhat","microsoft","euvd","jvn","advisory","epss");
    private IntelligenceSourceRegistry() { }
    public static String setting(String evidenceSource) {
        if(evidenceSource==null) return "";
        String source=evidenceSource.toLowerCase(Locale.ROOT).replace('_','-');
        if(source.contains("redhat")) return "redhat";
        if(source.contains("microsoft")) return "microsoft";
        if(source.equals("japan-vulndb")) return "jvn";
        if(source.startsWith("nvd") || source.startsWith("backfill")) return "nvd";
        return source;
    }
    public static boolean applicable(String source) { return SOURCES.contains(setting(source)) && !Set.of("kev","epss").contains(setting(source)); }
    public static boolean enabled(String source,Set<String> enabled) { return enabled.contains(setting(source)); }
}
