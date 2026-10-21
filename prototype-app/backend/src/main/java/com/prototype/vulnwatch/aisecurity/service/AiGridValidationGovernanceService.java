package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.LinkedHashSet;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AiGridValidationGovernanceService {
    private static final List<String> LABELS = List.of(
            "TRUE_POSITIVE", "FALSE_POSITIVE", "TRUE_NEGATIVE", "FALSE_NEGATIVE", "EXCLUDE");
    private static final List<String> ANSWER_KEY_OUTPUTS = List.of(
            "inventory", "technologies", "capabilities", "facts", "relationships", "applicability",
            "decisions", "findings", "gaps", "closureTransitions");

    private final NamedParameterJdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final ObjectMapper objectMapper;
    private final TenantSchemaExecutionService tenantExecution;
    private final TenantService tenants;

    private org.springframework.beans.factory.ObjectProvider<AiGridTenantPolicyDefaultsService> tenantDefaults;
    private com.prototype.vulnwatch.service.AuditEventService rolloutAudit;
    @org.springframework.beans.factory.annotation.Autowired
    void configureTenantDefaults(org.springframework.beans.factory.ObjectProvider<AiGridTenantPolicyDefaultsService> defaults,
            com.prototype.vulnwatch.service.AuditEventService rolloutAudit) {
        this.tenantDefaults=defaults; this.rolloutAudit=rolloutAudit;
    }

    public AiGridValidationGovernanceService(NamedParameterJdbcTemplate jdbc, TransactionTemplate transactions,
                                             ObjectMapper objectMapper,
                                             TenantSchemaExecutionService tenantExecution, TenantService tenants) {
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.objectMapper = objectMapper;
        this.tenantExecution = tenantExecution;
        this.tenants = tenants;
    }

    public AnswerKeyEnvironment createEnvironment(EnvironmentCommand command, String actor) {
        requireText(command.environmentKey(), "environmentKey");
        requireText(command.version(), "version");
        requireText(command.provider(), "provider");
        requireText(command.resourceFamily(), "resourceFamily");
        requireText(command.engineeringOwner(), "engineeringOwner");
        requireText(command.securityReviewer(), "securityReviewer");
        requireText(command.changeSummary(), "changeSummary");
        if (command.engineeringOwner().equalsIgnoreCase(command.securityReviewer())) {
            throw badRequest("engineeringOwner and securityReviewer must be independent");
        }
        if (command.providerApiVersions() == null || command.providerApiVersions().isEmpty()) {
            throw badRequest("providerApiVersions are required");
        }
        if (command.expectedEconomics() == null || command.expectedEconomics().isEmpty()) {
            throw badRequest("expectedEconomics are required");
        }
        if (command.reviewDueAt() == null || !command.reviewDueAt().isAfter(Instant.now())) {
            throw badRequest("reviewDueAt must be in the future");
        }
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            UUID id = UUID.randomUUID();
            jdbc.update("""
                    insert into platform.ai_grid_answer_key_environments
                        (id, environment_key, version, provider, resource_family, engineering_owner,
                         security_reviewer, provider_api_versions_json, expected_economics_json,
                         change_summary, review_due_at, created_by)
                    values (:id, :key, :version, :provider, :family, :owner, :reviewer,
                            cast(:apis as jsonb), cast(:economics as jsonb), :summary, :due, :actor)
                    """, new MapSqlParameterSource()
                    .addValue("id", id).addValue("key", command.environmentKey()).addValue("version", command.version())
                    .addValue("provider", command.provider()).addValue("family", command.resourceFamily())
                    .addValue("owner", command.engineeringOwner()).addValue("reviewer", command.securityReviewer())
                    .addValue("apis", json(command.providerApiVersions())).addValue("economics", json(command.expectedEconomics()))
                    .addValue("summary", command.changeSummary())
                    .addValue("due", java.sql.Timestamp.from(command.reviewDueAt()))
                    .addValue("actor", actor));
            return environment(id);
        }));
    }

    public AnswerKeyCase addCase(UUID environmentId, CaseCommand command, String actor) {
        requireText(command.caseKey(), "caseKey");
        requireText(command.scenario(), "scenario");
        requireText(command.labelVersion(), "labelVersion");
        requireText(command.rationale(), "rationale");
        requireText(command.evidenceReference(), "evidenceReference");
        if ((command.policyId() == null) != (command.policyVersion() == null)) {
            throw badRequest("policyId and policyVersion must be supplied together");
        }
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            assertEnvironmentLifecycle(environmentId, "DRAFT");
            UUID id = UUID.randomUUID();
            jdbc.update("""
                    insert into platform.ai_grid_answer_key_cases
                        (id, environment_id, case_key, scenario, policy_id, policy_version,
                         expected_applicability, expected_decision, expected_finding, expected_json,
                         label_version, rationale, evidence_reference, created_by)
                    values (:id, :environmentId, :caseKey, :scenario, :policyId, :policyVersion,
                            :applicability, :decision, :finding, cast(:expected as jsonb),
                            :labelVersion, :rationale, :evidence, :actor)
                    """, new MapSqlParameterSource().addValue("id", id).addValue("environmentId", environmentId)
                    .addValue("caseKey", command.caseKey()).addValue("scenario", command.scenario())
                    .addValue("policyId", command.policyId()).addValue("policyVersion", command.policyVersion())
                    .addValue("applicability", command.expectedApplicability())
                    .addValue("decision", command.expectedDecision()).addValue("finding", command.expectedFinding())
                    .addValue("expected", json(command.expected())).addValue("labelVersion", command.labelVersion())
                    .addValue("rationale", command.rationale()).addValue("evidence", command.evidenceReference())
                    .addValue("actor", actor));
            return answerKeyCase(id);
        }));
    }

    public AnswerKeyEnvironment certifyEnvironment(UUID environmentId, String actor) {
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            AnswerKeyEnvironment environment = environment(environmentId);
            if (!"DRAFT".equals(environment.lifecycle())) throw conflict("Only a draft answer key can be certified");
            List<String> blockers = certificationBlockers(environmentId);
            if (!blockers.isEmpty()) throw conflict("Answer key certification is blocked: " + String.join("; ", blockers));
            jdbc.update("""
                    update platform.ai_grid_answer_key_environments set lifecycle = 'RETIRED'
                     where environment_key = :key and lifecycle = 'CERTIFIED' and id <> :id
                    """, Map.of("key", environment.environmentKey(), "id", environmentId));
            jdbc.update("""
                    update platform.ai_grid_answer_key_environments
                       set lifecycle = 'CERTIFIED', certified_at = now()
                     where id = :id
                    """, Map.of("id", environmentId));
            return environment(environmentId);
        }));
    }

    public AnswerKeyRun recordRun(UUID environmentId, RunCommand command, String actor) {
        requireText(command.catalogDigest(), "catalogDigest");
        if (command.sourceTenantId() == null) throw badRequest("sourceTenantId is required");
        if (command.sourceRunId() == null) throw badRequest("sourceRunId is required");
        if (command.results() == null || command.results().isEmpty()) throw badRequest("results are required");
        List<AnswerKeyCase> declaredCases = cases(environmentId);
        RunProvenance provenance = validateRunProvenance(command, declaredCases);
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            AnswerKeyEnvironment environment = environment(environmentId);
            if (!"CERTIFIED".equals(environment.lifecycle()) || !environment.reviewDueAt().isAfter(Instant.now())) {
                throw conflict("Answer key is not currently certified and fresh");
            }
            List<AnswerKeyCase> cases = cases(environmentId);
            Map<String, ResultCommand> supplied = new HashMap<>();
            for (ResultCommand result : command.results()) {
                if (supplied.put(result.caseKey(), result) != null) throw badRequest("Duplicate result: " + result.caseKey());
            }
            if (supplied.size() != cases.size() || cases.stream().anyMatch(c -> !supplied.containsKey(c.caseKey()))) {
                throw conflict("Run must report exactly one result for every answer-key case");
            }
            UUID runId = UUID.randomUUID();
            int matched = 0;
            List<ResultInsert> resultRows = new ArrayList<>();
            for (AnswerKeyCase answerCase : cases) {
                ResultCommand result = supplied.get(answerCase.caseKey());
                boolean matches = parse(answerCase.expectedJson()).equals(objectMapper.valueToTree(result.observed()));
                if (matches) matched++;
                resultRows.add(new ResultInsert(answerCase.id(), result, matches));
            }
            String runStatus = matched == cases.size() ? "PASS" : "FAIL";
            jdbc.update("""
                    insert into platform.ai_grid_answer_key_runs
                        (id, environment_id, catalog_digest, status, total_cases, matched_cases,
                         executed_by, started_at, source_tenant_id, source_run_id, provenance_state)
                    values (:id, :environmentId, :digest, :status, :total, :matched, :actor, :started,
                            :sourceTenantId, :sourceRunId, 'PLATFORM_RUN_BOUND')
                    """, new MapSqlParameterSource().addValue("id", runId).addValue("environmentId", environmentId)
                    .addValue("digest", command.catalogDigest()).addValue("status", runStatus)
                    .addValue("total", cases.size()).addValue("matched", matched).addValue("actor", actor)
                    .addValue("sourceTenantId", command.sourceTenantId()).addValue("sourceRunId", command.sourceRunId())
                    .addValue("started", java.sql.Timestamp.from(
                            command.startedAt() == null ? Instant.now() : command.startedAt())));
            for (ResultInsert row : resultRows) {
                AssessmentProvenance assessment = provenance.assessments().get(row.command().caseKey());
                jdbc.update("""
                        insert into platform.ai_grid_answer_key_results
                            (id, run_id, case_id, observed_json, matched, mismatch_reason,
                             source_assessment_id, source_decision_fingerprint)
                        values (:id, :runId, :caseId, cast(:observed as jsonb), :matched, :reason,
                                :assessmentId, :decisionFingerprint)
                        """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("runId", runId)
                        .addValue("caseId", row.caseId()).addValue("observed", json(row.command().observed()))
                        .addValue("matched", row.matched())
                        .addValue("reason", row.matched() ? null : row.command().mismatchReason())
                        .addValue("assessmentId", assessment == null ? null : assessment.id())
                        .addValue("decisionFingerprint", assessment == null ? null : assessment.decisionFingerprint()));
            }
            if ("PASS".equals(runStatus)) {
                jdbc.update("update platform.ai_grid_answer_key_environments set last_verified_at = now() where id = :id",
                        Map.of("id", environmentId));
            }
            return answerKeyRun(runId);
        }));
    }

    private RunProvenance validateRunProvenance(RunCommand command, List<AnswerKeyCase> cases) {
        Map<String, ResultCommand> supplied = new HashMap<>();
        for (ResultCommand result : command.results()) {
            if (result == null || result.caseKey() == null) throw badRequest("Every result requires caseKey");
            if (supplied.put(result.caseKey(), result) != null) throw badRequest("Duplicate result: " + result.caseKey());
        }
        if (supplied.size() != cases.size() || cases.stream().anyMatch(c -> !supplied.containsKey(c.caseKey()))) {
            throw conflict("Run must report exactly one result for every answer-key case");
        }
        return tenantExecution.run(command.sourceTenantId(), () -> {
            Integer manifests = jdbc.queryForObject("""
                    select count(*) from ai_grid_snapshot_manifests where run_id = :runId
                    """, Map.of("runId", command.sourceRunId()), Integer.class);
            if (manifests == null || manifests == 0) {
                throw conflict("sourceRunId does not identify an immutable AI Grid snapshot for sourceTenantId");
            }
            Map<String, AssessmentProvenance> validated = new HashMap<>();
            for (AnswerKeyCase answerCase : cases) {
                ResultCommand result = supplied.get(answerCase.caseKey());
                if (answerCase.policyId() == null) {
                    if (result.sourceAssessmentId() != null) {
                        throw conflict("Non-policy answer-key case must not claim a source assessment: "
                                + answerCase.caseKey());
                    }
                    continue;
                }
                if (result.sourceAssessmentId() == null) {
                    throw conflict("Policy answer-key case requires sourceAssessmentId: " + answerCase.caseKey());
                }
                AssessmentProvenance assessment = jdbc.query("""
                        select a.id, a.policy_id, a.policy_version, a.applicability, a.decision,
                               a.decision_fingerprint,
                               exists (select 1 from findings f where f.assessment_id = a.id
                                        and f.status in ('OPEN','SUPPRESSED')) finding_present
                          from ai_grid_assessments a
                         where a.id = :assessmentId and a.run_id = :runId
                        """, Map.of("assessmentId", result.sourceAssessmentId(), "runId", command.sourceRunId()),
                        rs -> rs.next() ? new AssessmentProvenance(rs.getObject("id", UUID.class),
                                rs.getString("policy_id"), rs.getString("policy_version"),
                                rs.getString("applicability"), rs.getString("decision"),
                                rs.getString("decision_fingerprint"), rs.getBoolean("finding_present")) : null);
                if (assessment == null
                        || !answerCase.policyId().equals(assessment.policyId())
                        || !answerCase.policyVersion().equals(assessment.policyVersion())) {
                    throw conflict("sourceAssessmentId is not from the declared run and policy: "
                            + answerCase.caseKey());
                }
                if (assessment.decisionFingerprint() == null || assessment.decisionFingerprint().isBlank()) {
                    throw conflict("Source assessment has no deterministic decision fingerprint: "
                            + answerCase.caseKey());
                }
                JsonNode observed = objectMapper.valueToTree(result.observed());
                if (!assessment.applicability().equals(observed.path("applicability").asText())
                        || !assessment.decision().equals(observed.path("decisions").asText())
                        || assessment.findingPresent() != observed.path("findings").asBoolean()) {
                    throw conflict("Observed applicability, decision, or finding does not match source assessment: "
                            + answerCase.caseKey());
                }
                validated.put(answerCase.caseKey(), assessment);
            }
            return new RunProvenance(Map.copyOf(validated));
        });
    }

    public PrecisionReview createPrecisionReview(PrecisionReviewCommand command, String actor) {
        requireText(command.policyId(), "policyId");
        requireText(command.policyVersion(), "policyVersion");
        requireText(command.populationDefinition(), "populationDefinition");
        requireText(command.samplingMethod(), "samplingMethod");
        if (command.minimumSampleSize() <= 0) throw badRequest("minimumSampleSize must be positive");
        String digest = policyDigest(command.policyId(), command.policyVersion());
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            UUID id = UUID.randomUUID();
            jdbc.update("""
                    insert into platform.ai_grid_precision_reviews
                        (id, policy_id, policy_version, population_definition, sampling_method,
                         minimum_sample_size, confidence_level, precision_threshold,
                         material_change_digest, created_by)
                    values (:id, :policyId, :version, :population, :sampling, :minimum,
                            :confidence, :threshold, :digest, :actor)
                    """, new MapSqlParameterSource().addValue("id", id).addValue("policyId", command.policyId())
                    .addValue("version", command.policyVersion()).addValue("population", command.populationDefinition())
                    .addValue("sampling", command.samplingMethod()).addValue("minimum", command.minimumSampleSize())
                    .addValue("confidence", command.confidenceLevel() == null ? 0.95 : command.confidenceLevel())
                    .addValue("threshold", command.precisionThreshold() == null ? 0.95 : command.precisionThreshold())
                    .addValue("digest", digest).addValue("actor", actor));
            return precisionReview(id);
        }));
    }

    public PrecisionSample addPrecisionSample(UUID reviewId, PrecisionSampleCommand command) {
        requireText(command.sampleKey(), "sampleKey");
        requireText(command.provider(), "provider");
        requireText(command.resourceFamily(), "resourceFamily");
        requireText(command.severity(), "severity");
        requireText(command.observedOutcome(), "observedOutcome");
        requireText(command.evidenceReference(), "evidenceReference");
        if (command.sourceTenantId() == null || command.sourceRunId() == null || command.sourceAssessmentId() == null) {
            throw badRequest("Precision samples require sourceTenantId, sourceRunId, and sourceAssessmentId");
        }
        PrecisionReview review = precisionReview(reviewId);
        PrecisionSampleProvenance provenance = validatePrecisionSampleProvenance(review, command);
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            assertReviewOpen(reviewId);
            UUID id = UUID.randomUUID();
            jdbc.update("""
                    insert into platform.ai_grid_precision_samples
                        (id, review_id, sample_key, provider, resource_family, severity,
                         observed_outcome, predicted_finding, evidence_reference, source_tenant_id, source_run_id,
                         source_assessment_id, source_decision_fingerprint, provenance_state)
                    values (:id, :reviewId, :key, :provider, :family, :severity, :outcome, :predicted, :evidence,
                            :tenantId, :runId, :assessmentId, :fingerprint, 'PLATFORM_RUN_BOUND')
                    """, new MapSqlParameterSource().addValue("id", id).addValue("reviewId", reviewId)
                    .addValue("key", command.sampleKey()).addValue("provider", command.provider())
                    .addValue("family", command.resourceFamily()).addValue("severity", command.severity())
                    .addValue("outcome", command.observedOutcome()).addValue("predicted", command.predictedFinding())
                    .addValue("evidence", command.evidenceReference()).addValue("tenantId", command.sourceTenantId())
                    .addValue("runId", command.sourceRunId()).addValue("assessmentId", command.sourceAssessmentId())
                    .addValue("fingerprint", provenance.decisionFingerprint()));
            jdbc.update("update platform.ai_grid_precision_reviews set status = 'IN_REVIEW' where id = :id",
                    Map.of("id", reviewId));
            return precisionSample(id);
        }));
    }

    private PrecisionSampleProvenance validatePrecisionSampleProvenance(PrecisionReview review, PrecisionSampleCommand command) {
        PolicyCandidate candidate = policyCandidate(review.policyId(), review.policyVersion());
        boolean providerMatches = candidate.provider() == null || candidate.provider().isBlank()
                || candidate.provider().equals(command.provider());
        if (!providerMatches || !candidate.severity().equals(command.severity())) {
            throw conflict("Precision sample provider and severity must match the reviewed policy");
        }
        return tenantExecution.run(command.sourceTenantId(), () -> {
            Integer manifests = jdbc.queryForObject("select count(*) from ai_grid_snapshot_manifests where run_id = :runId",
                    Map.of("runId", command.sourceRunId()), Integer.class);
            if (manifests == null || manifests == 0) {
                throw conflict("sourceRunId does not identify an immutable AI Grid snapshot for sourceTenantId");
            }
            PrecisionSampleProvenance source = jdbc.query("""
                    select a.id, a.policy_id, a.policy_version, a.decision, a.decision_fingerprint,
                           exists (select 1 from findings f where f.assessment_id = a.id) finding_present
                      from ai_grid_assessments a
                     where a.id = :assessmentId and a.run_id = :runId
                    """, Map.of("assessmentId", command.sourceAssessmentId(), "runId", command.sourceRunId()), rs -> rs.next()
                    ? new PrecisionSampleProvenance(rs.getObject("id", UUID.class), rs.getString("policy_id"),
                    rs.getString("policy_version"), rs.getString("decision"), rs.getString("decision_fingerprint"),
                    rs.getBoolean("finding_present")) : null);
            if (source == null || !review.policyId().equals(source.policyId())
                    || !review.policyVersion().equals(source.policyVersion())) {
                throw conflict("sourceAssessmentId is not from the declared run and reviewed policy");
            }
            if (source.decisionFingerprint() == null || source.decisionFingerprint().isBlank()) {
                throw conflict("Source assessment has no deterministic decision fingerprint");
            }
            if (!command.observedOutcome().equals(source.decision()) || command.predictedFinding() != source.findingPresent()) {
                throw conflict("Precision sample outcome or predicted finding does not match source assessment");
            }
            return source;
        });
    }

    public void submitLabel(UUID reviewId, UUID sampleId, LabelCommand command, String actor) {
        if (!LABELS.contains(command.label())) throw badRequest("Invalid precision label");
        requireText(command.labelVersion(), "labelVersion");
        requireText(command.rationale(), "rationale");
        requireText(command.evidenceReference(), "evidenceReference");
        TenantContext.runAsPlatform(() -> transactions.executeWithoutResult(status -> {
            assertReviewOpen(reviewId);
            Boolean predicted = jdbc.query("""
                    select predicted_finding from platform.ai_grid_precision_samples
                     where id = :sampleId and review_id = :reviewId
                    """, Map.of("sampleId", sampleId, "reviewId", reviewId),
                    rs -> rs.next() ? rs.getBoolean(1) : null);
            if (predicted == null) throw notFound("Precision sample not found");
            if (predicted && !List.of("TRUE_POSITIVE", "FALSE_POSITIVE", "EXCLUDE").contains(command.label())) {
                throw badRequest("A predicted finding must be labelled TRUE_POSITIVE, FALSE_POSITIVE, or EXCLUDE");
            }
            if (!predicted && !List.of("TRUE_NEGATIVE", "FALSE_NEGATIVE", "EXCLUDE").contains(command.label())) {
                throw badRequest("A non-finding sample must be labelled TRUE_NEGATIVE, FALSE_NEGATIVE, or EXCLUDE");
            }
            jdbc.update("""
                    insert into platform.ai_grid_precision_labels
                        (id, sample_id, reviewer, label, label_version, rationale, evidence_reference)
                    values (:id, :sampleId, :reviewer, :label, :version, :rationale, :evidence)
                    """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("sampleId", sampleId)
                    .addValue("reviewer", actor).addValue("label", command.label())
                    .addValue("version", command.labelVersion()).addValue("rationale", command.rationale())
                    .addValue("evidence", command.evidenceReference()));
        }));
    }

    public void adjudicate(UUID reviewId, UUID sampleId, AdjudicationCommand command, String actor) {
        if (!LABELS.contains(command.finalLabel())) throw badRequest("Invalid final precision label");
        requireText(command.rationale(), "rationale");
        TenantContext.runAsPlatform(() -> transactions.executeWithoutResult(status -> {
            assertReviewOpen(reviewId);
            List<String> labels = jdbc.query("""
                    select l.label from platform.ai_grid_precision_labels l
                    join platform.ai_grid_precision_samples s on s.id = l.sample_id
                    where s.id = :sampleId and s.review_id = :reviewId and l.reviewer <> :actor
                    """, Map.of("sampleId", sampleId, "reviewId", reviewId, "actor", actor),
                    (rs, n) -> rs.getString(1));
            if (labels.size() < 2 || labels.stream().distinct().count() < 2) {
                throw conflict("Adjudication requires two disagreeing independent reviewer labels");
            }
            jdbc.update("""
                    insert into platform.ai_grid_precision_adjudications
                        (id, sample_id, final_label, rationale, adjudicated_by)
                    values (:id, :sampleId, :label, :rationale, :actor)
                    """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("sampleId", sampleId)
                    .addValue("label", command.finalLabel()).addValue("rationale", command.rationale())
                    .addValue("actor", actor));
        }));
    }

    public PrecisionReview assessBias(UUID reviewId, boolean passed, String rationale, String actor) {
        requireText(rationale, "rationale");
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            assertReviewOpen(reviewId);
            jdbc.update("""
                    update platform.ai_grid_precision_reviews
                       set bias_status = :bias, bias_rationale = :rationale, bias_reviewed_by = :actor
                     where id = :id
                    """, Map.of("bias", passed ? "PASSED" : "FAILED", "rationale", rationale,
                    "actor", actor, "id", reviewId));
            return precisionReview(reviewId);
        }));
    }

    public PrecisionReview finalizePrecisionReview(UUID reviewId) {
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            PrecisionReview review = precisionReview(reviewId);
            assertReviewOpen(reviewId);
            String severity = policySeverity(review.policyId(), review.policyVersion());
            int reviewersRequired = List.of("HIGH", "CRITICAL").contains(severity) ? 2 : 1;
            List<ResolvedSample> samples = jdbc.query("""
                    select s.id, s.predicted_finding,
                           coalesce(array_agg(l.label order by l.reviewer) filter (where l.label is not null),
                                    ARRAY[]::varchar[]) labels,
                           count(distinct l.reviewer) reviewer_count,
                           a.final_label
                      from platform.ai_grid_precision_samples s
                      left join platform.ai_grid_precision_labels l on l.sample_id = s.id
                      left join platform.ai_grid_precision_adjudications a on a.sample_id = s.id
                     where s.review_id = :id
                     group by s.id, s.predicted_finding, a.final_label
                     order by s.id
                    """, Map.of("id", reviewId), (rs, n) -> {
                String[] labels = (String[]) rs.getArray("labels").getArray();
                return new ResolvedSample(rs.getBoolean("predicted_finding"), List.of(labels),
                        rs.getInt("reviewer_count"), rs.getString("final_label"));
            });
            if (samples.isEmpty()) throw conflict("Precision review has no samples");
            int tp = 0;
            int fp = 0;
            for (ResolvedSample sample : samples) {
                if (sample.reviewerCount() < reviewersRequired) {
                    throw conflict("Every sample requires " + reviewersRequired + " independent reviewer label(s)");
                }
                String resolved = resolve(sample);
                if (resolved == null) {
                    jdbc.update("update platform.ai_grid_precision_reviews set status = 'ADJUDICATION' where id = :id",
                            Map.of("id", reviewId));
                    throw conflict("Reviewer disagreement requires adjudication");
                }
                if (sample.predictedFinding() && "TRUE_POSITIVE".equals(resolved)) tp++;
                if (sample.predictedFinding() && "FALSE_POSITIVE".equals(resolved)) fp++;
            }
            int positive = tp + fp;
            Double precision = positive == 0 || positive < review.minimumSampleSize()
                    || !"PASSED".equals(review.biasStatus()) ? null : (double) tp / positive;
            double[] interval = precision == null ? new double[]{Double.NaN, Double.NaN}
                    : wilson(tp, positive, review.confidenceLevel());
            boolean passed = precision != null && interval[0] >= review.precisionThreshold();
            jdbc.update("""
                    update platform.ai_grid_precision_reviews
                       set status = :status, resolved_positive_samples = :positive,
                           true_positives = :tp, false_positives = :fp, precision_value = :precision,
                           confidence_lower = :lower, confidence_upper = :upper, finalized_at = now()
                     where id = :id
                    """, new MapSqlParameterSource().addValue("status", passed ? "PASSED" : "FAILED")
                    .addValue("positive", positive).addValue("tp", tp).addValue("fp", fp)
                    .addValue("precision", precision).addValue("lower", precision == null ? null : interval[0])
                    .addValue("upper", precision == null ? null : interval[1]).addValue("id", reviewId));
            return precisionReview(reviewId);
        }));
    }

    public String policyDigest(String policyId, String version) {
        return TenantContext.runAsPlatform(() -> digest(policyCandidate(policyId, version).digestMaterial()));
    }

    /** Creates an immutable, digest-bound approval without exposing the policy to tenants. */
    public PolicyApproval approvePolicy(String policyId, String actor) {
        return approvePolicy(policyId, null, actor);
    }

    public PolicyApproval approvePolicy(String policyId, String tenantTestNote, String actor) {
        if (AiRuntimeScope.runtimePolicy(policyId, null)) AiRuntimeScope.requireInScope();
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            String version = singleCurrentVersion(policyId);
            PolicyCandidate candidate = policyCandidate(policyId, version);
            String digest = digest(candidate.digestMaterial());
            AnswerKeyGate answerKey = answerKeyGate(policyId, version, digest);
            PrecisionReview precision = candidate.requiresPrecisionReview()
                    ? passingPrecisionReview(policyId, version, digest) : null;
            boolean devTestApproval = tenantTestNote != null && !tenantTestNote.isBlank()
                    && hasDevTestDeployment(policyId, version);
            List<String> blockers = new ArrayList<>();
            if (actor.equals(candidate.authoredBy())) blockers.add("Independent author and approver are required");
            if (!devTestApproval && answerKey == null) blockers.add("No fresh, certified, passing answer-key run for this policy digest");
            if (!devTestApproval && candidate.requiresPrecisionReview() && precision == null) blockers.add("No passing precision review for this policy digest");
            UUID decisionId = UUID.randomUUID();
            if (!blockers.isEmpty()) {
                insertReleaseDecision(decisionId, policyId, version, "BLOCKED", answerKey, precision,
                        String.join("; ", blockers), actor, digest);
                return new PolicyApproval(decisionId, policyId, version, digest, false, String.join("; ", blockers));
            }
            if (!List.of("VALIDATED", "APPROVED").contains(candidate.lifecycle())) {
                String reason = "Policy lifecycle must be VALIDATED or APPROVED";
                insertReleaseDecision(decisionId, policyId, version, "BLOCKED", answerKey, precision, reason, actor, digest);
                return new PolicyApproval(decisionId, policyId, version, digest, false, reason);
            }
            String packageDigest = candidate.packageDigest() == null ? digest : candidate.packageDigest();
            if (candidate.packageDigest() == null) {
                jdbc.update("update platform.ai_grid_policy_versions set package_digest=:digest where policy_id=:policyId and version=:version",
                        Map.of("digest", packageDigest, "policyId", policyId, "version", version));
            }
            String approvalReason = devTestApproval
                    ? "Dev/test deployment evidence accepted; Tenant test result: " + tenantTestNote.trim()
                    : "Answer-key and precision release gates passed"
                        + (tenantTestNote == null || tenantTestNote.isBlank() ? "" : "; Tenant test result: " + tenantTestNote.trim());
            insertReleaseDecision(decisionId, policyId, version, "APPROVED", answerKey, precision,
                    approvalReason, actor, packageDigest);
            jdbc.update("""
                    update platform.ai_grid_policy_versions set lifecycle='APPROVED', approved_by=:actor,
                        approved_at=coalesce(approved_at,now()) where policy_id=:policyId and version=:version
                    """, Map.of("actor", actor, "policyId", policyId, "version", version));
            return new PolicyApproval(decisionId, policyId, version, digest, true,
                    approvalReason);
        }));
    }

    private boolean hasDevTestDeployment(String policyId, String version) {
        Boolean exists = jdbc.queryForObject("""
                select exists(
                    select 1 from platform.ai_grid_policy_dev_deployments
                     where policy_id=:policyId and policy_version=:version
                )
                """, Map.of("policyId", policyId, "version", version), Boolean.class);
        return Boolean.TRUE.equals(exists);
    }

    private boolean hasDevTestDeploymentForTenant(String policyId, String version, UUID tenantId) {
        Boolean exists = TenantContext.runAsPlatform(() -> jdbc.queryForObject("""
                select exists(
                    select 1 from platform.ai_grid_policy_dev_deployments
                     where policy_id=:policyId and policy_version=:version
                       and target_tenant_ids_json @> cast(:tenantId as jsonb)
                )
                """, Map.of("policyId", policyId, "version", version,
                "tenantId", json(List.of(tenantId))), Boolean.class));
        return Boolean.TRUE.equals(exists);
    }

    /** Deploys a validated package to explicit dev/test tenants without approving it. */
    public DevDeployment deployToDevTenants(String policyId, List<UUID> targetTenantIds, String testNote, String actor) {
        if (AiRuntimeScope.runtimePolicy(policyId, null)) AiRuntimeScope.requireInScope();
        if (targetTenantIds == null || targetTenantIds.isEmpty()) throw badRequest("Select at least one dev/test tenant");
        if (new LinkedHashSet<>(targetTenantIds).size() != targetTenantIds.size()) throw badRequest("Dev/test cohort contains duplicate tenant IDs");
        List<Tenant> cohort = targetTenantIds.stream().map(tenants::requireTenantUuid).toList();
        for (Tenant tenant : cohort) if (!"ACTIVE".equals(tenant.getStatus())) throw conflict("Dev/test cohort contains an inactive tenant");
        requireText(testNote, "testNote");
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            String version = singleCurrentVersion(policyId);
            PolicyCandidate candidate = policyCandidate(policyId, version);
            if (!"VALIDATED".equals(candidate.lifecycle())) throw conflict("Only VALIDATED policies can be deployed to dev/test tenants");
            String ids = json(targetTenantIds);
            UUID deploymentId = UUID.randomUUID();
            jdbc.update("""
                    insert into platform.ai_grid_policy_dev_deployments
                        (id,policy_id,policy_version,target_tenant_ids_json,test_note,deployed_by)
                    values (:id,:policyId,:version,cast(:targets as jsonb),:note,:actor)
                    """, new MapSqlParameterSource().addValue("id", deploymentId).addValue("policyId", policyId)
                    .addValue("version", version).addValue("targets", ids).addValue("note", testNote.trim()).addValue("actor", actor));
            jdbc.update("""
                    update platform.ai_grid_policy_distribution
                       set available=true, rollout_stage='DEV', canary_tenant_ids_json=cast(:targets as jsonb),
                           pinned_version=:version, updated_by=:actor, updated_at=now()
                     where policy_id=:policyId
                    """, new MapSqlParameterSource().addValue("policyId", policyId).addValue("version", version)
                    .addValue("targets", ids).addValue("actor", actor));
            return new DevDeployment(deploymentId, policyId, version, targetTenantIds, testNote.trim());
        }));
    }

    /** Publishes an already-approved policy to an explicit active canary cohort. */
    public PolicyPublication publishApprovedPolicy(String policyId, PublishCommand command, String actor) {
        if (AiRuntimeScope.runtimePolicy(policyId, null)) AiRuntimeScope.requireInScope();
        boolean publishAll = command != null && command.publishAll();
        if (!publishAll && (command == null || command.targetTenantIds() == null
                || command.targetTenantIds().isEmpty())) {
            throw badRequest("Select at least one tenant or publish to all active tenants");
        }
        List<UUID> tenantIds = publishAll
                ? tenants.listTenants().stream().filter(t -> "ACTIVE".equals(t.getStatus())).map(Tenant::getId).toList()
                : command.targetTenantIds();
        if (tenantIds.isEmpty()) throw conflict("No active tenants are available for publication");
        if (new LinkedHashSet<>(tenantIds).size() != tenantIds.size()) throw badRequest("CANARY cohort contains duplicate tenant IDs");
        List<Tenant> cohort = tenantIds.stream().map(tenants::requireTenantUuid).toList();
        String currentVersion = TenantContext.runAsPlatform(() -> singleCurrentVersion(policyId));
        for (Tenant tenant : cohort) {
            if (!"ACTIVE".equals(tenant.getStatus())) throw conflict("CANARY cohort contains an inactive tenant");
            UUID snapshotRunId = tenantExecution.run(tenant, () -> jdbc.query("""
                select run_id from ai_grid_snapshot_manifests group by run_id
                 order by max(observed_at) desc limit 1
                """, rs -> rs.next() ? rs.getObject(1, UUID.class) : null));
            if (snapshotRunId == null && !hasDevTestDeploymentForTenant(policyId, currentVersion, tenant.getId())) {
                throw conflict("CANARY cohort tenant lacks a complete snapshot or dev/test deployment: " + tenant.getSlug());
            }
        }
        String proposedDefault=TenantContext.runAsPlatform(() -> jdbc.queryForObject(
                "select default_selection from platform.ai_grid_policy_versions where policy_id=:id and version=:version",
                Map.of("id",policyId,"version",currentVersion),String.class));
        long changedDefaults=tenantDefaults.getObject().countSavedDefaultTransitions(cohort,policyId,proposedDefault);
        for (Tenant tenant:cohort) tenantExecution.run(tenant,() -> rolloutAudit.recordExplicitActor(
                tenant.getId(),actor,"PLATFORM_OWNER","ai_grid.policy_defaults.rollout_impact","ai_grid_policy",policyId,
                "{\"affectedTenantPolicyPairs\":"+changedDefaults+"}","SUCCESS"));
        String rolloutStage = publishAll ? "GENERAL_AVAILABILITY" : "CANARY";
        // GA is not a canary cohort. Keep the target list in the release binding for
        // audit/rollout work, but expose an empty canary list in distribution metadata.
        String tenantIdsJson = json(tenantIds);
        String canaryTenantIdsJson = json(publishAll ? List.of() : tenantIds);
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            String version = singleCurrentVersion(policyId);
            PolicyCandidate candidate = policyCandidate(policyId, version);
            String digest = digest(candidate.digestMaterial());
            String packageDigest = candidate.packageDigest();
            UUID approvalId = jdbc.query("""
                    select id from platform.ai_grid_policy_release_decisions
                     where policy_id=:policyId and policy_version=:version and decision='APPROVED'
                       and approved_package_digest=:packageDigest
                     order by decided_at desc limit 1
                    """, Map.of("policyId", policyId, "version", version, "packageDigest", packageDigest),
                    rs -> rs.next() ? rs.getObject(1, UUID.class) : null);
            if (approvalId == null) throw conflict("A current digest-bound approval is required before publishing");
            if (!"APPROVED".equals(candidate.lifecycle())) throw conflict("Policy lifecycle must be APPROVED");
            UUID bindingId = UUID.randomUUID();
            String distribution = json(Map.of("available", true, "rolloutStage", rolloutStage,
                    "canaryTenantIds", publishAll ? List.of() : tenantIds,
                    "targetTenantIds", tenantIds, "pinnedVersion", version));
            try {
                jdbc.update("""
                        insert into platform.ai_grid_policy_release_bindings
                            (id,approval_decision_id,policy_id,policy_version,approved_package_digest,
                             distribution_snapshot_json,target_tenant_ids_json,bound_by)
                        values (:id,:approval,:policyId,:version,:packageDigest,cast(:distribution as jsonb),
                                cast(:targets as jsonb),:actor)
                        """, new MapSqlParameterSource().addValue("id", bindingId).addValue("approval", approvalId)
                        .addValue("policyId", policyId).addValue("version", version).addValue("packageDigest", packageDigest)
                        .addValue("distribution", distribution).addValue("targets", tenantIdsJson)
                        .addValue("actor", actor));
            } catch (org.springframework.dao.DuplicateKeyException ex) {
                throw conflict("This approved policy is already bound for release");
            }
            jdbc.update("""
                    update platform.ai_grid_policy_versions set lifecycle='PUBLISHED', published_at=now()
                     where policy_id=:policyId and version=:version and lifecycle='APPROVED'
                    """, Map.of("policyId", policyId, "version", version));
            jdbc.update("""
                    insert into platform.ai_grid_policy_distribution
                        (policy_id,available,default_selection,rollout_stage,canary_tenant_ids_json,pinned_version,
                         approved_package_digest,release_decision_id,updated_by)
                    values (:policyId,true,:selection,:stage,cast(:canaryTenants as jsonb),:version,
                            :packageDigest,:approval,:actor)
                    on conflict (policy_id) do update set available=true, rollout_stage=excluded.rollout_stage,
                        canary_tenant_ids_json=excluded.canary_tenant_ids_json, pinned_version=excluded.pinned_version,
                        approved_package_digest=excluded.approved_package_digest,
                        release_decision_id=excluded.release_decision_id,
                        updated_by=excluded.updated_by, updated_at=now()
                    """, new MapSqlParameterSource().addValue("policyId", policyId).addValue("selection", defaultSelection(policyId, version))
                    .addValue("stage", rolloutStage).addValue("canaryTenants", canaryTenantIdsJson).addValue("version", version).addValue("packageDigest", packageDigest)
                    .addValue("approval", approvalId).addValue("actor", actor));
            UUID rolloutId = UUID.randomUUID();
            jdbc.update("""
                    insert into platform.ai_grid_policy_rollouts
                        (id,release_id,release_type,policy_id,previous_version,new_version,package_digest,
                         approved_package_digest,release_decision_id,distribution_snapshot_json,status)
                    values (:id,:binding,'POLICY_VERSION',:policyId,null,:version,:packageDigest,
                            :packageDigest,:approval,cast(:distribution as jsonb),'PENDING')
                    """, new MapSqlParameterSource().addValue("id", rolloutId).addValue("binding", bindingId.toString())
                    .addValue("policyId", policyId).addValue("version", version).addValue("packageDigest", packageDigest)
                    .addValue("approval", approvalId).addValue("distribution", distribution));
            for (UUID tenantId : tenantIds) {
                jdbc.update("""
                        insert into platform.ai_grid_policy_rollout_tasks (id,rollout_id,tenant_id)
                        values (:id,:rolloutId,:tenantId)
                        """, Map.of("id", UUID.randomUUID(), "rolloutId", rolloutId, "tenantId", tenantId));
            }
            return new PolicyPublication(policyId, version, packageDigest, approvalId, bindingId, rolloutId, tenantIds);
        }));
    }

    public void revokeReleaseBinding(UUID bindingId, String reason, String actor) {
        requireText(reason, "reason");
        TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            int changed = jdbc.update("""
                    update platform.ai_grid_policy_release_bindings set state='REVOKED', revoked_at=now(),
                        revoked_by=:actor, revocation_reason=:reason where id=:id and state='ACTIVE'
                    """, Map.of("id", bindingId, "actor", actor, "reason", reason.trim()));
            if (changed == 0) throw notFound("Active release binding not found");
            jdbc.update("""
                    update platform.ai_grid_policy_rollout_tasks set status='CANCELLED',
                        failure_detail='Cancelled: release binding revoked', completed_at=now(), updated_at=now(),
                        claim_token=null, lease_expires_at=null
                     where rollout_id in (select id from platform.ai_grid_policy_rollouts where release_id=:binding)
                       and status in ('PENDING','FAILED','WAITING_FOR_SNAPSHOT','WAITING_FOR_ASSESSMENT','PROCESSING')
                    """, Map.of("binding", bindingId.toString()));
            return null;
        }));
    }

    public String policyDigest(String policyId) {
        String version = TenantContext.runAsPlatform(() -> singleCurrentVersion(policyId));
        return policyDigest(policyId, version);
    }

    public ReleaseReadiness releaseReadiness(String policyId) {
        String version = TenantContext.runAsPlatform(() -> singleCurrentVersion(policyId));
        return releaseReadiness(policyId, version);
    }

    public ReleaseReadiness releaseReadiness(String policyId, String version) {
        return TenantContext.runAsPlatform(() -> {
            PolicyCandidate candidate = policyCandidate(policyId, version);
            String digest = digest(candidate.digestMaterial());
            AnswerKeyGate answerKey = answerKeyGate(policyId, version, digest);
            PrecisionReview precision = candidate.requiresPrecisionReview()
                    ? passingPrecisionReview(policyId, version, digest) : null;
            LatestDecision latest = jdbc.query("""
                    select decision, reason, decided_at from platform.ai_grid_policy_release_decisions
                     where policy_id = :policyId and policy_version = :version
                     order by decided_at desc limit 1
                    """, Map.of("policyId", policyId, "version", version), rs -> rs.next()
                    ? new LatestDecision(rs.getString("decision"), rs.getString("reason"),
                    rs.getTimestamp("decided_at").toInstant()) : null);
            List<String> blockers = new ArrayList<>();
            if (answerKey == null) blockers.add("FRESH_PASSING_ANSWER_KEY_REQUIRED");
            if (candidate.requiresPrecisionReview() && precision == null) {
                blockers.add("PASSING_PRECISION_REVIEW_REQUIRED");
            }
            if (!List.of("VALIDATED", "APPROVED", "CANARY", "PUBLISHED").contains(candidate.lifecycle())) {
                blockers.add("POLICY_LIFECYCLE_NOT_RELEASABLE");
            }
            return new ReleaseReadiness(policyId, version, candidate.lifecycle(), candidate.severity(), digest,
                    blockers.isEmpty(), blockers, answerKey == null ? null : answerKey.runId(),
                    precision == null ? null : precision.id(), latest == null ? null : latest.decision(),
                    latest == null ? null : latest.reason(), latest == null ? null : latest.decidedAt());
        });
    }

    /** Platform-wide, read-only evidence ledger for the complete AGCF Phase 1 release family. */
    public Phase1CertificationReadiness phase1CertificationReadiness() {
        return TenantContext.runAsPlatform(() -> {
            List<PolicyRef> policies = jdbc.query("""
                    select policy_id, version from platform.ai_grid_policy_versions
                     where release_family = 'AGCF_PHASE_1'
                     order by policy_id, version
                    """, (rs, n) -> new PolicyRef(rs.getString("policy_id"), rs.getString("version")));
            List<Phase1PolicyCertification> policyReadiness = policies.stream().map(policy -> {
                ReleaseReadiness readiness = releaseReadiness(policy.policyId(), policy.version());
                return new Phase1PolicyCertification(policy.policyId(), policy.version(), readiness.catalogDigest(),
                        readiness.answerKeyRunId() != null, readiness.precisionReviewId() != null,
                        readiness.ready(), readiness.blockers());
            }).toList();
            long answerKeyReady = policyReadiness.stream().filter(Phase1PolicyCertification::answerKeyReady).count();
            long precisionReady = policyReadiness.stream().filter(Phase1PolicyCertification::precisionReady).count();
            long releaseReady = policyReadiness.stream().filter(Phase1PolicyCertification::releaseReady).count();
            return new Phase1CertificationReadiness(policyReadiness.size(), answerKeyReady, precisionReady,
                    releaseReady, policyReadiness.size() - releaseReady, policyReadiness);
        });
    }

    /**
     * Materializes the repository-owned Phase 1 certification corpus as immutable draft answer
     * keys. This creates no run result, reviewer label, precision review, or release decision.
     */
    public Phase1CorpusBootstrap bootstrapPhase1Corpus(Phase1CorpusBootstrapCommand command, String actor) {
        requireText(command.engineeringOwner(), "engineeringOwner");
        requireText(command.securityReviewer(), "securityReviewer");
        if (command.engineeringOwner().equalsIgnoreCase(command.securityReviewer())) {
            throw badRequest("engineeringOwner and securityReviewer must be independent");
        }
        if (command.reviewDueAt() == null || !command.reviewDueAt().isAfter(Instant.now())) {
            throw badRequest("reviewDueAt must be in the future");
        }
        return TenantContext.runAsPlatform(() -> {
            JsonNode corpus = phase1Corpus();
            String environmentVersion = "AGCF_PHASE_1_" + corpus.path("sourceManifestDigest").asText().substring(0, 12);
            Map<String, JsonNode> policies = new HashMap<>();
            corpus.path("policies").forEach(policy -> policies.put(policy.path("policyId").asText(), policy));
            Map<String, List<JsonNode>> casesByPolicy = new HashMap<>();
            corpus.path("cases").forEach(certificationCase -> casesByPolicy
                    .computeIfAbsent(certificationCase.path("policyId").asText(), ignored -> new ArrayList<>())
                    .add(certificationCase));
            int environmentsCreated = 0;
            int casesCreated = 0;
            for (Map.Entry<String, JsonNode> entry : policies.entrySet()) {
                String policyId = entry.getKey();
                JsonNode policy = entry.getValue();
                List<JsonNode> cases = casesByPolicy.getOrDefault(policyId, List.of());
                if (cases.isEmpty()) throw new IllegalStateException("Certification corpus has no cases for " + policyId);
                String environmentKey = "AGCF_PHASE_1_" + policyId;
                AnswerKeyEnvironment environment = environmentByKeyAndVersion(environmentKey, environmentVersion);
                if (environment == null) {
                    environment = createEnvironment(new EnvironmentCommand(environmentKey, environmentVersion,
                            policy.path("provider").asText(), "AGCF_" + policy.path("provider").asText(),
                            command.engineeringOwner(), command.securityReviewer(),
                            Map.of("catalog", "AGCF_PHASE_1", "packageDigest", policy.path("packageDigest").asText()),
                            Map.of("caseCount", cases.size(), "contentRead", false, "writePermissions", false),
                            "Generated from digest-bound Phase 1 certification corpus", command.reviewDueAt()), actor);
                    environmentsCreated++;
                }
                if (!"DRAFT".equals(environment.lifecycle())) continue;
                java.util.Set<String> existingCases = cases(environment.id()).stream()
                        .map(AnswerKeyCase::caseKey).collect(java.util.stream.Collectors.toSet());
                for (JsonNode certificationCase : cases) {
                    if (!existingCases.add(certificationCase.path("caseKey").asText())) continue;
                    addCase(environment.id(), new CaseCommand(
                            certificationCase.path("caseKey").asText(), certificationCase.path("scenario").asText(),
                            policyId, certificationCase.path("policyVersion").asText(),
                            certificationCase.path("expectedApplicability").asText(),
                            certificationCase.path("expectedDecision").asText(), certificationCase.path("expectedFinding").asBoolean(),
                            objectMapper.convertValue(certificationCase.path("expected"), new TypeReference<Map<String, Object>>() {}),
                            certificationCase.path("labelVersion").asText(), certificationCase.path("rationale").asText(),
                            certificationCase.path("evidenceReference").asText()), actor);
                    casesCreated++;
                }
            }
            return new Phase1CorpusBootstrap(corpus.path("sourceManifestDigest").asText(), policies.size(),
                    environmentsCreated, casesCreated);
        });
    }

    /**
     * Certifies only complete, digest-bound corpus drafts. It deliberately records no run,
     * reviewer label, precision review, or release approval.
     */
    public Phase1CorpusCertification certifyPhase1Corpus(String actor) {
        return TenantContext.runAsPlatform(() -> {
            Phase1CorpusReadiness readiness = phase1CorpusReadiness();
            int certified = 0;
            int alreadyCertified = 0;
            List<String> blocked = new ArrayList<>();
            for (Phase1CorpusEnvironment environment : readiness.environments()) {
                if (environment.environmentId() == null) {
                    blocked.add(environment.policyId() + ": environment has not been bootstrapped");
                } else if ("CERTIFIED".equals(environment.lifecycle())) {
                    alreadyCertified++;
                } else if (!"DRAFT".equals(environment.lifecycle())) {
                    blocked.add(environment.policyId() + ": environment lifecycle is " + environment.lifecycle());
                } else if (!environment.certificationBlockers().isEmpty()) {
                    blocked.add(environment.policyId() + ": " + String.join(", ", environment.certificationBlockers()));
                } else {
                    certifyEnvironment(environment.environmentId(), actor);
                    certified++;
                }
            }
            return new Phase1CorpusCertification(readiness.sourceManifestDigest(), readiness.totalPolicies(),
                    certified, alreadyCertified, List.copyOf(blocked));
        });
    }

    /** Read-only operational view of all repository-owned Phase 1 corpus environments. */
    public Phase1CorpusReadiness phase1CorpusReadiness() {
        return TenantContext.runAsPlatform(() -> {
            JsonNode corpus = phase1Corpus();
            String version = "AGCF_PHASE_1_" + corpus.path("sourceManifestDigest").asText().substring(0, 12);
            List<Phase1CorpusEnvironment> rows = new ArrayList<>();
            for (JsonNode policy : corpus.path("policies")) {
                String policyId = policy.path("policyId").asText();
                AnswerKeyEnvironment environment = environmentByKeyAndVersion("AGCF_PHASE_1_" + policyId, version);
                if (environment == null) {
                    rows.add(new Phase1CorpusEnvironment(policyId, policy.path("policyVersion").asText(), null, null,
                            0, List.of("ENVIRONMENT_NOT_BOOTSTRAPPED")));
                } else {
                    rows.add(new Phase1CorpusEnvironment(policyId, policy.path("policyVersion").asText(), environment.id(),
                            environment.lifecycle(), cases(environment.id()).size(), certificationBlockers(environment.id())));
                }
            }
            long certified = rows.stream().filter(row -> "CERTIFIED".equals(row.lifecycle())).count();
            long drafts = rows.stream().filter(row -> "DRAFT".equals(row.lifecycle())).count();
            long missing = rows.stream().filter(row -> row.environmentId() == null).count();
            long blocked = rows.stream().filter(row -> row.environmentId() != null && !row.certificationBlockers().isEmpty()).count();
            return new Phase1CorpusReadiness(corpus.path("sourceManifestDigest").asText(), rows.size(), certified,
                    drafts, missing, blocked, List.copyOf(rows));
        });
    }

    public List<AnswerKeyEnvironment> environments() {
        return TenantContext.runAsPlatform(() -> jdbc.query("""
                select * from platform.ai_grid_answer_key_environments
                 order by environment_key, created_at desc
                """, (rs, n) -> mapEnvironment(rs)));
    }

    public List<AnswerKeyCase> cases(UUID environmentId) {
        return TenantContext.runAsPlatform(() -> jdbc.query("""
                select id, environment_id, case_key, scenario, policy_id, policy_version,
                       expected_applicability, expected_decision, expected_finding,
                       expected_json::text, label_version, rationale, evidence_reference
                  from platform.ai_grid_answer_key_cases where environment_id = :id order by case_key
                """, Map.of("id", environmentId), (rs, n) -> new AnswerKeyCase(rs.getObject("id", UUID.class),
                rs.getObject("environment_id", UUID.class), rs.getString("case_key"), rs.getString("scenario"),
                rs.getString("policy_id"), rs.getString("policy_version"), rs.getString("expected_applicability"),
                rs.getString("expected_decision"), (Boolean) rs.getObject("expected_finding"),
                rs.getString("expected_json"), rs.getString("label_version"), rs.getString("rationale"),
                rs.getString("evidence_reference"))));
    }

    public PrecisionReview precisionReview(UUID id) {
        return TenantContext.runAsPlatform(() -> {
            PrecisionReview result = jdbc.query("""
                    select * from platform.ai_grid_precision_reviews where id = :id
                    """, Map.of("id", id), rs -> rs.next() ? mapPrecisionReview(rs) : null);
            if (result == null) throw notFound("Precision review not found");
            return result;
        });
    }

    private AnswerKeyEnvironment environment(UUID id) {
        AnswerKeyEnvironment result = jdbc.query("select * from platform.ai_grid_answer_key_environments where id = :id",
                Map.of("id", id), rs -> rs.next() ? mapEnvironment(rs) : null);
        if (result == null) throw notFound("Answer-key environment not found");
        return result;
    }

    private List<String> certificationBlockers(UUID environmentId) {
        Map<String, Integer> scenarioCounts = jdbc.query("""
                select scenario, count(*) count from platform.ai_grid_answer_key_cases
                 where environment_id = :id group by scenario
                """, Map.of("id", environmentId), rs -> {
            Map<String, Integer> counts = new HashMap<>();
            while (rs.next()) counts.put(rs.getString("scenario"), rs.getInt("count"));
            return counts;
        });
        List<String> blockers = new ArrayList<>();
        if (scenarioCounts.getOrDefault("SECURE", 0) == 0 || scenarioCounts.getOrDefault("INSECURE", 0) == 0) {
            blockers.add("SECURE_AND_INSECURE_CASE_REQUIRED");
        }
        if (scenarioCounts.getOrDefault("PROXY_VS_VERIFIED", 0) == 0) {
            blockers.add("PROXY_VS_VERIFIED_CASE_REQUIRED");
        }
        java.util.Set<String> declaredOutputs = new java.util.HashSet<>();
        for (AnswerKeyCase answerKeyCase : cases(environmentId)) {
            parse(answerKeyCase.expectedJson()).fieldNames().forEachRemaining(declaredOutputs::add);
        }
        List<String> missingOutputs = ANSWER_KEY_OUTPUTS.stream()
                .filter(output -> !declaredOutputs.contains(output)).toList();
        if (!missingOutputs.isEmpty()) blockers.add("EXPECTED_OUTPUTS_MISSING:" + String.join(",", missingOutputs));
        return List.copyOf(blockers);
    }

    private AnswerKeyEnvironment environmentByKeyAndVersion(String environmentKey, String version) {
        return jdbc.query("""
                select * from platform.ai_grid_answer_key_environments
                 where environment_key = :key and version = :version
                 order by case lifecycle when 'DRAFT' then 1 when 'CERTIFIED' then 2 else 3 end, created_at desc
                 limit 1
                """, Map.of("key", environmentKey, "version", version), rs -> rs.next() ? mapEnvironment(rs) : null);
    }

    private JsonNode phase1Corpus() {
        try (java.io.InputStream input = new ClassPathResource(
                "ai-grid/certification/agcf-phase-1-answer-key-corpus.json").getInputStream()) {
            JsonNode corpus = objectMapper.readTree(input);
            if (!"AGCF_PHASE_1".equals(corpus.path("releaseFamily").asText())
                    || corpus.path("sourceManifestDigest").asText().length() != 64) {
                throw new IllegalStateException("Invalid bundled AGCF Phase 1 certification corpus");
            }
            return corpus;
        } catch (java.io.IOException exception) {
            throw new IllegalStateException("Unable to load bundled AGCF Phase 1 certification corpus", exception);
        }
    }

    private AnswerKeyCase answerKeyCase(UUID id) {
        return jdbc.queryForObject("""
                select id, environment_id, case_key, scenario, policy_id, policy_version,
                       expected_applicability, expected_decision, expected_finding,
                       expected_json::text, label_version, rationale, evidence_reference
                  from platform.ai_grid_answer_key_cases where id = :id
                """, Map.of("id", id), (rs, n) -> new AnswerKeyCase(rs.getObject("id", UUID.class),
                rs.getObject("environment_id", UUID.class), rs.getString("case_key"), rs.getString("scenario"),
                rs.getString("policy_id"), rs.getString("policy_version"), rs.getString("expected_applicability"),
                rs.getString("expected_decision"), (Boolean) rs.getObject("expected_finding"),
                rs.getString("expected_json"), rs.getString("label_version"), rs.getString("rationale"),
                rs.getString("evidence_reference")));
    }

    private AnswerKeyRun answerKeyRun(UUID id) {
        return jdbc.queryForObject("""
                select id, environment_id, catalog_digest, status, total_cases, matched_cases,
                       executed_by, started_at, completed_at, source_tenant_id, source_run_id, provenance_state
                  from platform.ai_grid_answer_key_runs where id = :id
                """, Map.of("id", id), (rs, n) -> new AnswerKeyRun(rs.getObject("id", UUID.class),
                rs.getObject("environment_id", UUID.class), rs.getString("catalog_digest"), rs.getString("status"),
                rs.getInt("total_cases"), rs.getInt("matched_cases"), rs.getString("executed_by"),
                rs.getTimestamp("started_at").toInstant(), rs.getTimestamp("completed_at").toInstant(),
                rs.getObject("source_tenant_id", UUID.class), rs.getObject("source_run_id", UUID.class),
                rs.getString("provenance_state")));
    }

    private PrecisionSample precisionSample(UUID id) {
        return jdbc.queryForObject("""
                select id, review_id, sample_key, provider, resource_family, severity,
                       observed_outcome, predicted_finding, evidence_reference, source_tenant_id, source_run_id,
                       source_assessment_id, source_decision_fingerprint, provenance_state
                  from platform.ai_grid_precision_samples where id = :id
                """, Map.of("id", id), (rs, n) -> new PrecisionSample(rs.getObject("id", UUID.class),
                rs.getObject("review_id", UUID.class), rs.getString("sample_key"), rs.getString("provider"),
                rs.getString("resource_family"), rs.getString("severity"), rs.getString("observed_outcome"),
                rs.getBoolean("predicted_finding"), rs.getString("evidence_reference"),
                rs.getObject("source_tenant_id", UUID.class), rs.getObject("source_run_id", UUID.class),
                rs.getObject("source_assessment_id", UUID.class), rs.getString("source_decision_fingerprint"),
                rs.getString("provenance_state")));
    }

    private void assertEnvironmentLifecycle(UUID id, String lifecycle) {
        if (!lifecycle.equals(environment(id).lifecycle())) throw conflict("Answer-key environment is immutable after certification");
    }

    private void assertReviewOpen(UUID reviewId) {
        String state = jdbc.query("select status from platform.ai_grid_precision_reviews where id = :id",
                Map.of("id", reviewId), rs -> rs.next() ? rs.getString(1) : null);
        if (state == null) throw notFound("Precision review not found");
        if (List.of("PASSED", "FAILED", "STALE").contains(state)) throw conflict("Precision review is finalized");
    }

    private String resolve(ResolvedSample sample) {
        if (sample.finalLabel() != null) return sample.finalLabel();
        return sample.labels().stream().distinct().count() == 1 ? sample.labels().get(0) : null;
    }

    private AnswerKeyGate answerKeyGate(String policyId, String version, String digest) {
        return jdbc.query("""
                select r.id run_id, e.id environment_id
                  from platform.ai_grid_answer_key_runs r
                  join platform.ai_grid_answer_key_environments e on e.id = r.environment_id
                 where e.lifecycle = 'CERTIFIED' and e.review_due_at > now()
                   and r.status = 'PASS' and r.catalog_digest = :digest
                   and r.provenance_state = 'PLATFORM_RUN_BOUND'
                   and exists (select 1 from platform.ai_grid_answer_key_cases c
                                where c.environment_id = e.id and c.policy_id = :policyId
                                  and c.policy_version = :version)
                 order by r.completed_at desc limit 1
                """, Map.of("digest", digest, "policyId", policyId, "version", version),
                rs -> rs.next() ? new AnswerKeyGate(rs.getObject("run_id", UUID.class),
                        rs.getObject("environment_id", UUID.class)) : null);
    }

    private PrecisionReview passingPrecisionReview(String policyId, String version, String digest) {
        return jdbc.query("""
                select * from platform.ai_grid_precision_reviews
                 where policy_id = :policyId and policy_version = :version
                   and material_change_digest = :digest and status = 'PASSED'
                   and not exists (select 1 from platform.ai_grid_precision_samples sample
                                    where sample.review_id = ai_grid_precision_reviews.id
                                      and sample.provenance_state <> 'PLATFORM_RUN_BOUND')
                 order by finalized_at desc limit 1
                """, Map.of("policyId", policyId, "version", version, "digest", digest),
                rs -> rs.next() ? mapPrecisionReview(rs) : null);
    }

    private PolicyCandidate policyCandidate(String policyId, String version) {
        PolicyCandidate candidate = jdbc.query("""
                select provider, severity, lifecycle, authored_by, package_digest, release_family, concat_ws('|', policy_id, version, name, description, severity,
                       workflow_class, default_selection, artifact_types_json::text, native_kinds_json::text,
                       required_capabilities_json::text, required_relationships_json::text,
                       required_resource_families_json::text, required_facts_json::text,
                       predicate_json::text, reason_code, remediation, framework_mappings_json::text,
                       scope_resolution, parameter_definitions_json::text, package_digest, package_source_ref, release_notes,
                       replaces_policy_id, replaces_version) legacy_digest_material
                  from platform.ai_grid_policy_versions where policy_id = :policyId and version = :version
                """, Map.of("policyId", policyId, "version", version), rs -> rs.next()
                ? new PolicyCandidate(rs.getString("provider"), rs.getString("severity"), rs.getString("lifecycle"), rs.getString("authored_by"),
                rs.getString("package_digest"), rs.getString("release_family"), rs.getString("legacy_digest_material"))
                : null);
        if (candidate == null) throw notFound("AI Grid policy version not found");
        return candidate;
    }

    private String policySeverity(String policyId, String version) {
        String severity = jdbc.query("""
                select severity from platform.ai_grid_policy_versions
                 where policy_id=:id and version=:version
                union all
                select severity from platform.ai_grid_correlation_versions
                 where correlation_id=:id and version=:version
                limit 1
                """, Map.of("id", policyId, "version", version), rs -> rs.next() ? rs.getString(1) : null);
        if (severity == null) throw notFound("AI Grid policy or correlation version not found");
        return severity;
    }

    private void insertReleaseDecision(UUID id, String policyId, String version, String decision,
                                       AnswerKeyGate answerKey, PrecisionReview precision, String reason, String actor) {
        insertReleaseDecision(id, policyId, version, decision, answerKey, precision, reason, actor, null);
    }

    private void insertReleaseDecision(UUID id, String policyId, String version, String decision,
                                       AnswerKeyGate answerKey, PrecisionReview precision, String reason, String actor,
                                       String approvedDigest) {
        jdbc.update("""
                insert into platform.ai_grid_policy_release_decisions
                    (id, policy_id, policy_version, package_digest, decision, answer_key_run_id,
                     precision_review_id, reason, decided_by, approved_package_digest)
                values (:id, :policyId, :version, :digest, :decision, :answerKey, :precision, :reason, :actor, :digest)
                """, new MapSqlParameterSource().addValue("id", id).addValue("policyId", policyId)
                .addValue("version", version).addValue("decision", decision)
                .addValue("answerKey", answerKey == null ? null : answerKey.runId())
                .addValue("precision", precision == null ? null : precision.id())
                .addValue("reason", reason).addValue("actor", actor).addValue("digest", approvedDigest));
    }

    private String singleCurrentVersion(String policyId) {
        List<String> versions = jdbc.query("""
                select version from platform.ai_grid_policy_versions
                 where policy_id=:policyId and lifecycle not in ('DEPRECATED','RETIRED')
                 order by created_at desc, version desc
                """, Map.of("policyId", policyId), (rs, row) -> rs.getString(1));
        if (versions.isEmpty()) throw notFound("AI Grid policy not found or unavailable");
        if (versions.size() != 1) throw conflict("Policy-ID release operations require exactly one current technical version");
        return versions.get(0);
    }

    private String defaultSelection(String policyId, String version) {
        return jdbc.query("select default_selection from platform.ai_grid_policy_versions where policy_id=:policyId and version=:version",
                Map.of("policyId", policyId, "version", version), rs -> rs.next() ? rs.getString(1) : null);
    }

    private AnswerKeyEnvironment mapEnvironment(java.sql.ResultSet rs) throws java.sql.SQLException {
        return new AnswerKeyEnvironment(rs.getObject("id", UUID.class), rs.getString("environment_key"),
                rs.getString("version"), rs.getString("provider"), rs.getString("resource_family"),
                rs.getString("lifecycle"), rs.getString("engineering_owner"), rs.getString("security_reviewer"),
                rs.getString("provider_api_versions_json"), rs.getString("expected_economics_json"),
                rs.getString("change_summary"), instant(rs, "certified_at"), instant(rs, "last_verified_at"),
                rs.getTimestamp("review_due_at").toInstant(), rs.getString("created_by"),
                rs.getTimestamp("created_at").toInstant());
    }

    private PrecisionReview mapPrecisionReview(java.sql.ResultSet rs) throws java.sql.SQLException {
        return new PrecisionReview(rs.getObject("id", UUID.class), rs.getString("policy_id"),
                rs.getString("policy_version"), rs.getString("population_definition"), rs.getString("sampling_method"),
                rs.getInt("minimum_sample_size"), rs.getDouble("confidence_level"),
                rs.getDouble("precision_threshold"), rs.getString("material_change_digest"),
                rs.getString("bias_status"), rs.getString("bias_rationale"), rs.getString("bias_reviewed_by"),
                rs.getString("status"), rs.getInt("resolved_positive_samples"), rs.getInt("true_positives"),
                rs.getInt("false_positives"), nullableDouble(rs, "precision_value"),
                nullableDouble(rs, "confidence_lower"), nullableDouble(rs, "confidence_upper"),
                instant(rs, "finalized_at"), rs.getString("created_by"), rs.getTimestamp("created_at").toInstant());
    }

    private Double nullableDouble(java.sql.ResultSet rs, String column) throws java.sql.SQLException {
        Object value = rs.getObject(column);
        return value == null ? null : ((Number) value).doubleValue();
    }

    private Instant instant(java.sql.ResultSet rs, String column) throws java.sql.SQLException {
        java.sql.Timestamp timestamp = rs.getTimestamp(column);
        return timestamp == null ? null : timestamp.toInstant();
    }

    private String json(Object value) {
        try {
            return objectMapper.writeValueAsString(value == null ? Map.of() : value);
        } catch (JsonProcessingException ex) {
            throw badRequest("Invalid JSON payload");
        }
    }

    private JsonNode parse(String value) {
        try {
            return objectMapper.readTree(value);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Stored answer-key JSON is invalid", ex);
        }
    }

    private String digest(String value) {
        try {
            return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private double[] wilson(int successes, int total, double confidenceLevel) {
        double z = confidenceLevel >= 0.99 ? 2.575829 : confidenceLevel >= 0.95 ? 1.959964 : 1.644854;
        double p = (double) successes / total;
        double denominator = 1 + z * z / total;
        double centre = (p + z * z / (2 * total)) / denominator;
        double margin = z * Math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denominator;
        return new double[]{Math.max(0, centre - margin), Math.min(1, centre + margin)};
    }

    private void requireText(String value, String field) {
        if (value == null || value.isBlank()) throw badRequest(field + " is required");
    }

    private ResponseStatusException badRequest(String message) { return new ResponseStatusException(HttpStatus.BAD_REQUEST, message); }
    private ResponseStatusException conflict(String message) { return new ResponseStatusException(HttpStatus.CONFLICT, message); }
    private ResponseStatusException notFound(String message) { return new ResponseStatusException(HttpStatus.NOT_FOUND, message); }
    private record ResultInsert(UUID caseId, ResultCommand command, boolean matched) {}
    private record RunProvenance(Map<String, AssessmentProvenance> assessments) {}
    private record AssessmentProvenance(UUID id, String policyId, String policyVersion, String applicability,
                                        String decision, String decisionFingerprint, boolean findingPresent) {}
    private record PrecisionSampleProvenance(UUID id, String policyId, String policyVersion, String decision,
                                             String decisionFingerprint, boolean findingPresent) {}
    private record ResolvedSample(boolean predictedFinding, List<String> labels, int reviewerCount, String finalLabel) {}
    private record PolicyCandidate(String provider, String severity, String lifecycle, String authoredBy, String packageDigest,
                                   String releaseFamily, String legacyDigestMaterial) {
        String digestMaterial() {
            return packageDigest == null || packageDigest.isBlank() ? legacyDigestMaterial : "package:" + packageDigest;
        }

        boolean requiresPrecisionReview() {
            return "AGCF_PHASE_1".equals(releaseFamily) || List.of("HIGH", "CRITICAL").contains(severity);
        }
    }
    private record AnswerKeyGate(UUID runId, UUID environmentId) {}
    private record LatestDecision(String decision, String reason, Instant decidedAt) {}
    private record PolicyRef(String policyId, String version) {}

    public record EnvironmentCommand(String environmentKey, String version, String provider, String resourceFamily,
                                     String engineeringOwner, String securityReviewer,
                                     Map<String, Object> providerApiVersions, Map<String, Object> expectedEconomics,
                                     String changeSummary, Instant reviewDueAt) {}
    public record CaseCommand(String caseKey, String scenario, String policyId, String policyVersion,
                              String expectedApplicability, String expectedDecision, Boolean expectedFinding,
                              Map<String, Object> expected, String labelVersion, String rationale,
                              String evidenceReference) {}
    public record RunCommand(UUID sourceTenantId, UUID sourceRunId, String catalogDigest,
                             Instant startedAt, List<ResultCommand> results) {}
    public record ResultCommand(String caseKey, UUID sourceAssessmentId,
                                Map<String, Object> observed, String mismatchReason) {}
    public record PrecisionReviewCommand(String policyId, String policyVersion, String populationDefinition,
                                         String samplingMethod, int minimumSampleSize, Double confidenceLevel,
                                         Double precisionThreshold) {}
    public record PrecisionSampleCommand(String sampleKey, String provider, String resourceFamily, String severity,
                                         String observedOutcome, boolean predictedFinding, String evidenceReference,
                                         UUID sourceTenantId, UUID sourceRunId, UUID sourceAssessmentId) {
        /** Kept only for source compatibility; source-unbound payloads are rejected before persistence. */
        public PrecisionSampleCommand(String sampleKey, String provider, String resourceFamily, String severity,
                                      String observedOutcome, boolean predictedFinding, String evidenceReference) {
            this(sampleKey, provider, resourceFamily, severity, observedOutcome, predictedFinding, evidenceReference,
                    null, null, null);
        }
    }
    public record LabelCommand(String label, String labelVersion, String rationale, String evidenceReference) {}
    public record AdjudicationCommand(String finalLabel, String rationale) {}
    public record AnswerKeyEnvironment(UUID id, String environmentKey, String version, String provider,
                                       String resourceFamily, String lifecycle, String engineeringOwner,
                                       String securityReviewer, String providerApiVersionsJson,
                                       String expectedEconomicsJson, String changeSummary, Instant certifiedAt,
                                       Instant lastVerifiedAt, Instant reviewDueAt, String createdBy, Instant createdAt) {}
    public record AnswerKeyCase(UUID id, UUID environmentId, String caseKey, String scenario, String policyId,
                                String policyVersion, String expectedApplicability, String expectedDecision,
                                Boolean expectedFinding, String expectedJson, String labelVersion,
                                String rationale, String evidenceReference) {}
    public record AnswerKeyRun(UUID id, UUID environmentId, String catalogDigest, String status, int totalCases,
                               int matchedCases, String executedBy, Instant startedAt, Instant completedAt,
                               UUID sourceTenantId, UUID sourceRunId, String provenanceState) {}
    public record PrecisionReview(UUID id, String policyId, String policyVersion, String populationDefinition,
                                  String samplingMethod, int minimumSampleSize, double confidenceLevel,
                                  double precisionThreshold, String materialChangeDigest, String biasStatus,
                                  String biasRationale, String biasReviewedBy, String status,
                                  int resolvedPositiveSamples, int truePositives, int falsePositives,
                                  Double precisionValue, Double confidenceLower, Double confidenceUpper,
                                  Instant finalizedAt, String createdBy, Instant createdAt) {}
    public record PrecisionSample(UUID id, UUID reviewId, String sampleKey, String provider, String resourceFamily,
                                  String severity, String observedOutcome, boolean predictedFinding,
                                  String evidenceReference, UUID sourceTenantId, UUID sourceRunId,
                                  UUID sourceAssessmentId, String sourceDecisionFingerprint, String provenanceState) {}
    public record PolicyApproval(UUID approvalId, String policyId, String policyVersion, String packageDigest,
                                 boolean approved, String reason) {}
    public record PolicyPublication(String policyId, String policyVersion, String packageDigest, UUID approvalId,
                                    UUID releaseBindingId, UUID rolloutId, List<UUID> targetTenantIds) {}
    public record PublishCommand(List<UUID> targetTenantIds, boolean publishAll) {
        public PublishCommand(List<UUID> targetTenantIds) { this(targetTenantIds, false); }
    }
    public record DevDeployment(UUID id, String policyId, String policyVersion, List<UUID> targetTenantIds, String testNote) {}
    public record ReleaseReadiness(String policyId, String policyVersion, String lifecycle, String severity,
                                   String catalogDigest, boolean ready, List<String> blockers,
                                   UUID answerKeyRunId, UUID precisionReviewId, String latestDecision,
                                   String latestDecisionReason, Instant latestDecisionAt) {}
    public record Phase1PolicyCertification(String policyId, String version, String catalogDigest,
                                            boolean answerKeyReady, boolean precisionReady, boolean releaseReady,
                                            List<String> blockers) {}
    public record Phase1CertificationReadiness(int totalPolicies, long answerKeyReadyPolicies,
                                               long precisionReadyPolicies, long releaseReadyPolicies,
                                               long pendingPolicies,
                                               List<Phase1PolicyCertification> policies) {}
    public record Phase1CorpusBootstrapCommand(String engineeringOwner, String securityReviewer, Instant reviewDueAt) {}
    public record Phase1CorpusBootstrap(String sourceManifestDigest, int policyCount,
                                        int environmentsCreated, int casesCreated) {}
    public record Phase1CorpusEnvironment(String policyId, String policyVersion, UUID environmentId, String lifecycle,
                                          int caseCount, List<String> certificationBlockers) {}
    public record Phase1CorpusReadiness(String sourceManifestDigest, int totalPolicies, long certifiedEnvironments,
                                        long draftEnvironments, long missingEnvironments, long blockedEnvironments,
                                        List<Phase1CorpusEnvironment> environments) {}
    public record Phase1CorpusCertification(String sourceManifestDigest, int totalPolicies, int environmentsCertified,
                                            int environmentsAlreadyCertified, List<String> blockedEnvironments) {}
}
