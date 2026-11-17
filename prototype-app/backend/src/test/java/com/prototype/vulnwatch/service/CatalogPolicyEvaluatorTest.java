package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.dto.CatalogPolicy;
import com.prototype.vulnwatch.dto.CatalogPolicy.*;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;
import static org.junit.jupiter.api.Assertions.*;

class CatalogPolicyEvaluatorTest {
    private final CatalogPolicyEvaluator evaluator = new CatalogPolicyEvaluator();
    private CatalogPolicy policy(Rule rule) {
        return new CatalogPolicy(1, Set.of("nvd", "kev"), false, ScoreResolution.MAX_ALLOWED_OBSERVATION_V1, rule);
    }
    private Rule numeric(Op op, Field field, double value) { return new Rule(op, field, value, null, null); }
    @Test void strictAndInclusiveThresholdsDiffer() {
        var facts = new CatalogPolicyEvaluator.Facts(2020, 6.0, 0.1, null);
        var gt = numeric(Op.GT, Field.CVSS, 6);
        var gte = numeric(Op.GTE, Field.CVSS, 6);
        evaluator.validate(policy(gt)); evaluator.validate(policy(gte));
        assertFalse(evaluator.matches(gt, facts, true)); assertTrue(evaluator.matches(gte, facts, true));
    }
    @Test void yearAndScoreOrKevPreservesBooleanGrouping() {
        var expression = new Rule(Op.ANY, null, null, null, List.of(
                new Rule(Op.ALL, null, null, null, List.of(numeric(Op.GTE, Field.PUBLICATION_YEAR, 2020), numeric(Op.GT, Field.CVSS, 6))),
                new Rule(Op.EQ, Field.CISA_KEV, null, true, null)));
        evaluator.validate(policy(expression));
        assertTrue(evaluator.matches(expression, new CatalogPolicyEvaluator.Facts(2021, 7.0, null, null), true));
        assertTrue(evaluator.matches(expression, new CatalogPolicyEvaluator.Facts(1999, null, null, true), true));
        assertFalse(evaluator.matches(expression, new CatalogPolicyEvaluator.Facts(2019, 9.0, 1.0, null), true));
    }
    @Test void unknownOnlyMatchesExplicitMissingRule() {
        var unknown = new CatalogPolicyEvaluator.Facts(null, null, null, null);
        assertFalse(evaluator.matches(numeric(Op.LT, Field.CVSS, 6), unknown, true));
        assertFalse(evaluator.matches(new Rule(Op.EQ, Field.CISA_KEV, null, false, null), unknown, true));
        var missing = new Rule(Op.MISSING, Field.CVSS, null, null, null);
        evaluator.validate(policy(missing)); assertTrue(evaluator.matches(missing, unknown, true));
    }
    @Test void sourcePresentRequiresNoPredicateValuesAndDoesNotRequireNumericFacts() {
        var present=new Rule(Op.SOURCE_PRESENT,null,null,null,null);
        evaluator.validate(policy(present));
        var unknown = new CatalogPolicyEvaluator.Facts(null, null, null, null);
        assertFalse(evaluator.matches(present, unknown, false));
        assertTrue(evaluator.matches(present, unknown, true));
        var grouped = new Rule(Op.ANY, null, null, null, List.of(present, numeric(Op.GT, Field.CVSS, 6)));
        evaluator.validate(policy(grouped));
        assertFalse(evaluator.matches(grouped, unknown, false));
        assertThrows(ResponseStatusException.class,()->evaluator.validate(policy(
                new Rule(Op.SOURCE_PRESENT,Field.CVSS,null,null,null))));
        assertThrows(ResponseStatusException.class,()->evaluator.validate(policy(
                new Rule(Op.SOURCE_PRESENT,null,null,null,List.of(present)))));
    }
    @Test void invalidNumbersAndTypesAreRejected() {
        for (Rule rule : List.of(numeric(Op.GT, Field.CVSS, 11), numeric(Op.GTE, Field.EPSS, 10),
                numeric(Op.EQ, Field.PUBLICATION_YEAR, 2020.5), numeric(Op.GT, Field.CVSS, Double.NaN),
                numeric(Op.GT, Field.CISA_KEV, 1), new Rule(Op.ALL, null, null, null, List.of())))
            assertThrows(ResponseStatusException.class, () -> evaluator.validate(policy(rule)));
    }
    @Test void excessiveDepthAndNodesAreRejected() {
        Rule nested = numeric(Op.GT, Field.CVSS, 6);
        for (int i = 0; i < 8; i++) nested = new Rule(Op.ALL, null, null, null, List.of(nested));
        CatalogPolicy deep = policy(nested);
        assertThrows(ResponseStatusException.class, () -> evaluator.validate(deep));
        var wide = policy(new Rule(Op.ALL, null, null, null, java.util.Collections.nCopies(64, numeric(Op.GT, Field.CVSS, 6))));
        assertThrows(ResponseStatusException.class, () -> evaluator.validate(wide));
    }
    @Test void unsupportedVersionSourceAndScoreModeFailClosed() {
        Rule rule = numeric(Op.GT, Field.CVSS, 6);
        for (CatalogPolicy invalid : List.of(new CatalogPolicy(2, Set.of("nvd"), false, ScoreResolution.MAX_ALLOWED_OBSERVATION_V1, rule),
                new CatalogPolicy(1, Set.of("arbitrary"), false, ScoreResolution.MAX_ALLOWED_OBSERVATION_V1, rule),
                new CatalogPolicy(1, Set.of("nvd"), false, null, rule)))
            assertThrows(ResponseStatusException.class, () -> evaluator.validate(invalid));
        evaluator.validate(new CatalogPolicy(1, Set.of("nvd"), false, ScoreResolution.MAX_ALLOWED_CVSS_V3_1, rule));
        evaluator.validate(new CatalogPolicy(1, Set.of("nvd"), false, ScoreResolution.MAX_ALLOWED_CVSS_V4_0, rule));
    }
}
