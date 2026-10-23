package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.*;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** The only sink used by feed normalizers. Successful runs freeze these complete row images. */
@Service
public class IntelligenceStagingService {
    public static final String POLICY_VERSION="sg-normalization-1";
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    public IntelligenceStagingService(JdbcTemplate jdbc,ObjectMapper mapper) { this.jdbc=jdbc;this.mapper=mapper; }

    public java.util.Optional<java.time.Instant> latestSuccessfulModified(String source) {
        return java.util.Optional.ofNullable(jdbc.queryForObject("select max((s.payload->>'lastModifiedAt')::timestamptz) from platform.intelligence_staged_records s join platform.sync_runs r on r.id=s.sync_run_id where s.kind='OBSERVATION' and s.source_system=? and lower(r.status) in ('completed','success')",java.sql.Timestamp.class,source)).map(java.sql.Timestamp::toInstant);
    }
    public UUID epssUpperId() { return jdbc.queryForObject("select max(id::text)::uuid from (select canonical_id id from platform.intelligence_identifiers union select id from platform.vulnerabilities) ids",UUID.class); }
    public java.util.List<Vulnerability> epssCandidates(java.time.Instant stale,UUID after,UUID upper,int size) {
        return jdbc.query("""
                select distinct i.canonical_id,i.identifier from (select canonical_id,identifier from platform.intelligence_identifiers union select id,external_id from platform.vulnerabilities) i
                left join platform.vulnerabilities v on v.id=i.canonical_id
                where i.identifier ~ '^CVE-[0-9]{4}-[0-9]{4,}$' and i.canonical_id<=? and (?::uuid is null or i.canonical_id>?::uuid)
                  and (v.epss_updated_at is null or v.epss_updated_at<?)
                  and (v.id is not null or exists(select 1 from platform.intelligence_staged_records s join platform.sync_runs r on r.id=s.sync_run_id
                       where s.canonical_id=i.canonical_id and s.kind='OBSERVATION' and lower(r.status) in ('completed','success')))
                order by i.canonical_id limit ?
                """,(rs,row) -> { Vulnerability value=new Vulnerability();value.setId(rs.getObject(1,UUID.class));value.setExternalId(rs.getString(2));return value; },upper,after,after,java.sql.Timestamp.from(stale),size);
    }

    @Transactional
    public VulnerabilityIntelligenceService.ObservationUpsertResult observation(VulnerabilityIntelligenceService.ObservationUpsertRequest request) {
        IntelligenceWriteContext.sourceRecord(request.sourceRecordId());
        String external=request.externalId()==null ? "" : request.externalId().trim().toUpperCase(java.util.Locale.ROOT);
        UUID proposed=UUID.nameUUIDFromBytes(("sg-vulnerability:"+external).getBytes(StandardCharsets.UTF_8));
        jdbc.update("""
                insert into platform.intelligence_identifiers(identifier,canonical_id)
                values(?,coalesce((select id from platform.vulnerabilities where external_id=?),?)) on conflict(identifier) do nothing
                """,external,external,proposed);
        UUID id=jdbc.queryForObject("select canonical_id from platform.intelligence_identifiers where identifier=?",UUID.class,external);
        String validation=external.isBlank() || external.length()>50 || (external.startsWith("CVE-") && !external.matches("CVE-[0-9]{4}-[0-9]{4,}"))
                ? "INVALID_IDENTIFIER" : "VALID";
        if((request.cvssScore()!=null && (!Double.isFinite(request.cvssScore()) || request.cvssScore()<0 || request.cvssScore()>10))
                || (request.epssScore()!=null && (!Double.isFinite(request.epssScore()) || request.epssScore()<0 || request.epssScore()>1))) validation="INVALID_SCORE";
        append("OBSERVATION",external,id,request.sourceSystem(),mapper.valueToTree(request),validation);
        if("ghsa".equals(request.sourceSystem()) && request.sourceRecordId()!=null && request.sourceRecordId().trim().toUpperCase(java.util.Locale.ROOT).startsWith("GHSA-")) {
            String verifiedAlias=request.sourceRecordId().trim().toUpperCase(java.util.Locale.ROOT);
            java.util.Set<String> structuredCves=new java.util.HashSet<>();
            try {
                var raw=mapper.readTree(request.rawPayload()==null ? "{}" : request.rawPayload());
                if(raw.path("cve_id").asText().matches("CVE-[0-9]{4}-[0-9]{4,}")) structuredCves.add(raw.path("cve_id").asText());
                for(var identifier:raw.path("identifiers")) if("CVE".equalsIgnoreCase(identifier.path("type").asText()) && identifier.path("value").asText().matches("CVE-[0-9]{4}-[0-9]{4,}")) structuredCves.add(identifier.path("value").asText());
            } catch(java.io.IOException failure) { /* Invalid provider JSON cannot establish an alias. */ }
            if(structuredCves.size()==1 && external.startsWith("CVE-")) {
                var existing=jdbc.queryForList("select distinct v.external_id from platform.intelligence_identifiers i join platform.vulnerabilities v on v.id=i.canonical_id where i.identifier=?",String.class,verifiedAlias);
                boolean conflicting=existing.stream().anyMatch(value -> value.startsWith("CVE-") && !value.equals(external));
                append("ALIAS",external,id,"ghsa",Map.of("identifier",verifiedAlias),conflicting ? "AMBIGUOUS_ALIAS" : "VALID");
            } else if(structuredCves.size()>1) append("ALIAS_RELATIONSHIP",external,id,"ghsa",Map.of("identifier",verifiedAlias,"canonicalIdentifiers",new java.util.TreeSet<>(structuredCves)),"VALID");
        }
        Vulnerability vulnerability=new Vulnerability();
        vulnerability.setId(id);vulnerability.setExternalId(external);vulnerability.setTitle(request.title()==null ? external : request.title());
        vulnerability.setSeverity(request.severity()==null ? "UNKNOWN" : request.severity());
        vulnerability.setSource(VulnerabilitySource.NVD);
        return new VulnerabilityIntelligenceService.ObservationUpsertResult(vulnerability,false,true);
    }

    public <T> T entity(String kind,Vulnerability vulnerability,String source,T entity) {
        if (entity instanceof VulnerabilityTarget target) target.setSourceRecordId(IntelligenceWriteContext.sourceRecord());
        var row=IntelligenceEntityCodec.row(entity);
        if(row.containsKey("id") && row.get("id")==null) {
            var identity=new java.util.TreeMap<>(row);
            identity.keySet().removeAll(java.util.Set.of("id","created_at","updated_at","kb_version"));
            row.put("id",UUID.nameUUIDFromBytes((kind+identity).getBytes(StandardCharsets.UTF_8)));
        }
        String validation="VALID";
        if(entity instanceof VulnerabilityTarget target && (target.getNormalizedTargetKey()==null || target.getNormalizedTargetKey().isBlank())) validation="INVALID_TARGET";
        append(kind,vulnerability.getExternalId(),vulnerability.getId(),source,mapper.valueToTree(row),validation);
        return entity;
    }
    public void replaceForRecord(Vulnerability vulnerability,java.util.List<String> sources,String sourceRecord) {
        append("REPLACE_TARGETS",vulnerability.getExternalId(),vulnerability.getId(),"",
                mapper.valueToTree(Map.of("sources",sources,"sourceRecordId",sourceRecord)),"VALID");
    }
    public void replace(Vulnerability vulnerability,String kind,java.util.List<String> sources) {
        append(kind,vulnerability.getExternalId(),vulnerability.getId(),"",mapper.valueToTree(sources),"VALID");
    }
    public void metadata(Vulnerability vulnerability,String source) {
        var row=IntelligenceEntityCodec.row(vulnerability);
        java.util.Set<String> fields=switch(source) {
            case "nvd" -> java.util.Set.of("vuln_status","cvss_version","cvss_vector","attack_vector","attack_complexity","privileges_required","user_interaction","scope","exploitability_score","impact_score");
            case "kev" -> java.util.Set.of("kev_date_added","kev_due_date","kev_required_action");
            case "epss" -> java.util.Set.of("epss_score","epss_updated_at");
            default -> throw new IllegalArgumentException("Unsupported metadata source");
        };
        row.keySet().retainAll(fields);
        append("METADATA",vulnerability.getExternalId(),vulnerability.getId(),source,mapper.valueToTree(row),"VALID");
    }
    public void append(String kind,String external,UUID canonical,String source,Object payload,String validation) {
        UUID run=IntelligenceWriteContext.runId();
        if(run==null) throw new IllegalStateException("Intelligence normalization requires an explicit staging run");
        try {
            jdbc.update("""
                    insert into platform.intelligence_staged_records(sync_run_id,kind,external_id,canonical_id,source_system,payload,validation)
                    values(?,?,?,?,?,?::jsonb,?)
                    """,run,kind,external,canonical,source==null ? "" : source,mapper.writeValueAsString(payload),validation);
        } catch(java.io.IOException failure) { throw new IllegalStateException("Cannot encode staged intelligence",failure); }
    }
}
