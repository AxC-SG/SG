package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.dto.CatalogPolicy;
import com.prototype.vulnwatch.dto.CatalogPolicy.Field;
import com.prototype.vulnwatch.dto.CatalogPolicy.Op;
import com.prototype.vulnwatch.dto.CatalogPolicy.Rule;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

/** Pure evaluator shared by preview and future catalog builds. Unknown never matches a comparison. */
@Component
public class CatalogPolicyEvaluator {
    public record Facts(Integer publicationYear, Double cvss, Double epss, Boolean cisaKev) {}

    public void validate(CatalogPolicy policy) {
        require(policy != null && policy.version() == 1, "Policy version must be 1");
        require(policy.scoreResolution() != null,
                "Explicit score resolution is required");
        require(policy.sources() != null && !policy.sources().isEmpty()
                && policy.sources().size() <= IntelligenceSourceRegistry.SOURCES.size(), "Sources are required");
        require(policy.sources().stream().allMatch(s -> s != null && IntelligenceSourceRegistry.SOURCES.contains(s)),
                "Sources must use supported canonical names");
        validateRule(policy.rule(), 1, new int[]{0});
    }

    private void validateRule(Rule rule, int depth, int[] count) {
        require(depth <= 8 && ++count[0] <= 64, "Policy is limited to depth 8 and 64 nodes");
        require(rule != null && rule.op() != null, "Each rule requires an operator");
        boolean group = rule.op() == Op.ALL || rule.op() == Op.ANY;
        if (group) {
            require(rule.field() == null && rule.number() == null && rule.flag() == null,
                    "Groups cannot contain predicate values");
            require(rule.children() != null && !rule.children().isEmpty() && rule.children().size() <= 64,
                    "Groups require 1 to 64 children");
            for (Rule child : rule.children()) validateRule(child, depth + 1, count);
            return;
        }
        if (rule.op() == Op.SOURCE_PRESENT) {
            require(rule.field() == null && rule.number() == null && rule.flag() == null
                    && (rule.children() == null || rule.children().isEmpty()),
                    "SOURCE_PRESENT cannot contain predicates or children");
            return;
        }
        require(rule.field() != null && (rule.children() == null || rule.children().isEmpty()),
                "Predicates require a field and cannot contain children");
        if (rule.op() == Op.MISSING) {
            require(rule.number() == null && rule.flag() == null, "MISSING cannot contain a value");
        } else if (rule.field() == Field.CISA_KEV) {
            require(rule.op() == Op.EQ && rule.flag() != null && rule.number() == null,
                    "CISA_KEV requires EQ and a boolean flag");
        } else {
            require(rule.flag() == null && rule.number() != null && Double.isFinite(rule.number()),
                    "Numeric predicates require a finite number");
            double max = switch (rule.field()) { case CVSS -> 10; case EPSS -> 1; default -> 9999; };
            require(rule.number() >= 0 && rule.number() <= max, "Threshold is outside the field range");
            if (rule.field() == Field.PUBLICATION_YEAR)
                require(rule.number() == Math.rint(rule.number()), "Publication year must be an integer");
        }
    }

    /** Call validate once before evaluating a batch; evidence must already be restricted to enabled selected sources. */
    public boolean matches(Rule rule, Facts facts, boolean allowedSourceEvidence) {
        if (rule.op() == Op.ALL) return rule.children().stream().allMatch(child -> matches(child, facts, allowedSourceEvidence));
        if (rule.op() == Op.ANY) return rule.children().stream().anyMatch(child -> matches(child, facts, allowedSourceEvidence));
        if (rule.op() == Op.SOURCE_PRESENT) return allowedSourceEvidence;
        Object value = switch (rule.field()) {
            case PUBLICATION_YEAR -> facts.publicationYear();
            case CVSS -> facts.cvss();
            case EPSS -> facts.epss();
            case CISA_KEV -> facts.cisaKev();
        };
        if (rule.op() == Op.MISSING) return value == null;
        if (value == null) return false;
        if (rule.field() == Field.CISA_KEV) return value.equals(rule.flag());
        double number = ((Number) value).doubleValue();
        if (!Double.isFinite(number)) return false;
        return switch (rule.op()) {
            case GT -> number > rule.number(); case GTE -> number >= rule.number();
            case LT -> number < rule.number(); case LTE -> number <= rule.number();
            case EQ -> number == rule.number(); default -> false;
        };
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }
}
