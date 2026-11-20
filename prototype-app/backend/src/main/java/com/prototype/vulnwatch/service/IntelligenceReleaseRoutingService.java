package com.prototype.vulnwatch.service;

import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/** Builds a bounded-read routing manifest in the same transaction as publication. */
@Service
public class IntelligenceReleaseRoutingService {
    private static final String RELEASE_TARGETS = """
            with targets as (
                select target_type, normalized_target_key, cpe_id::text, software_identity_id::text
                from platform.vulnerability_targets t
                join platform.intelligence_release_route_vulnerabilities r on r.vulnerability_id=t.vulnerability_id
                where r.release_id=?
                union
                select side.value->>'target_type', side.value->>'normalized_target_key',
                       side.value->>'cpe_id', side.value->>'software_identity_id'
                from platform.intelligence_release_changes j
                cross join lateral (values (j.previous_value),(j.new_value)) side(value)
                where j.release_id=? and j.table_name='vulnerability_targets' and side.value is not null
            )
            """;
    private final JdbcTemplate jdbc;
    private final boolean enabled;

    public IntelligenceReleaseRoutingService(JdbcTemplate jdbc,
            @Value("${app.intelligence.targeted-publication.enabled:false}") boolean enabled) {
        this.jdbc = jdbc;
        this.enabled = enabled;
    }

    boolean enabled() {
        return enabled;
    }

    String mode(UUID release) {
        return jdbc.queryForList("select mode from platform.intelligence_release_routes where release_id=?",
                String.class, release).stream().findFirst().orElse(null);
    }

    void capture(UUID release, UUID baseRelease) {
        if (!enabled || baseRelease == null) return;
        String mode = jdbc.queryForObject("""
                select case
                    when count(*)=0 or not bool_and(table_schema='platform'
                        and (previous_value is not null or new_value is not null)
                        and (table_name='vulnerabilities' or (
                            table_name in ('vulnerability_targets','vulnerability_rules','vulnerability_config_expr',
                                'vulnerability_intel_observations','vulnerability_intel_summary',
                                'vulnerability_intel_summary_sources','vex_assertions')
                            and (previous_value is null or coalesce(previous_value->>'vulnerability_id','')
                                ~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$')
                            and (new_value is null or coalesce(new_value->>'vulnerability_id','')
                                ~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$')))) then null
                    when bool_and(table_name in ('vulnerabilities','vulnerability_intel_summary')
                        and previous_value is not null and new_value is not null
                        and previous_value - array['epss_score','epss_updated_at','updated_at','summary_updated_at']
                            = new_value - array['epss_score','epss_updated_at','updated_at','summary_updated_at'])
                        then 'RANKING'
                    else 'APPLICABILITY' end
                from platform.intelligence_release_changes where release_id=?
                """, String.class, release);
        if (mode == null) return;

        jdbc.update("insert into platform.intelligence_release_routes (release_id,mode) values (?,?)", release, mode);
        jdbc.update("""
                insert into platform.intelligence_release_route_vulnerabilities (release_id,vulnerability_id)
                select distinct j.release_id, key.id::uuid
                from platform.intelligence_release_changes j
                cross join lateral (values
                    (case when j.table_name='vulnerabilities' then j.row_id::text end),
                    (j.previous_value->>'vulnerability_id'), (j.new_value->>'vulnerability_id')) key(id)
                where j.release_id=? and key.id is not null
                """, release);
        if ("RANKING".equals(mode)) return;

        boolean unresolved = Boolean.TRUE.equals(jdbc.queryForObject(RELEASE_TARGETS + """
                select exists (
                    select 1 from targets where not coalesce(case target_type
                        when 'CPE' then cpe_id is not null or software_identity_id is not null
                        when 'PURL' then nullif(btrim(normalized_target_key),'') is not null
                        when 'COORD' then normalized_target_key ~ '^[a-z0-9._+-]+:'
                        when 'ADVISORY_PACKAGE' then normalized_target_key ~ '^[a-z0-9._+-]+:'
                        else false end, false))
                """, Boolean.class, release, release));
        if (unresolved) {
            jdbc.update("delete from platform.intelligence_release_route_vulnerabilities where release_id=?", release);
            jdbc.update("delete from platform.intelligence_release_routes where release_id=?", release);
            return;
        }

        // Include current targets as well as both sides of changed targets. Old keys
        // reach installations that matched before a target was changed or removed.
        jdbc.update(RELEASE_TARGETS + """
                insert into platform.intelligence_release_route_targets (release_id,key_kind,match_key)
                select distinct ?, key.kind, key.value
                from targets t
                cross join lateral (values
                    ('CPE', case when t.target_type='CPE' then t.cpe_id end),
                    ('PURL', case when t.target_type='PURL' then t.normalized_target_key end),
                    ('ECOSYSTEM', case when t.target_type in ('COORD','ADVISORY_PACKAGE')
                        then split_part(t.normalized_target_key, ':', 1) end),
                    ('IDENTITY', t.software_identity_id)) key(kind,value)
                where nullif(key.value,'') is not null
                """, release, release, release);
    }

    List<UUID> componentPage(UUID release, UUID after) {
        return jdbc.queryForList("""
                with keys as (select key_kind, match_key from platform.intelligence_release_route_targets where release_id=?),
                changed as (select vulnerability_id from platform.intelligence_release_route_vulnerabilities where release_id=?)
                select id from (
                    select i.id from inventory_components i join keys k
                      on k.key_kind='PURL' and (k.match_key=i.normalized_purl
                          or lower(regexp_replace(i.purl, '^[[:space:][:cntrl:]]+|[[:space:][:cntrl:]]+$', '', 'g'))=k.match_key
                          or octet_length(i.purl)<>char_length(i.purl))
                    union
                    select i.id from inventory_components i join keys k
                      on k.key_kind='IDENTITY' and i.software_identity_id=case when k.key_kind='IDENTITY' then k.match_key::uuid end
                    union
                    select i.id from inventory_components i join keys k on k.key_kind='ECOSYSTEM'
                      and (lower(regexp_replace(i.ecosystem, '^[[:space:][:cntrl:]]+|[[:space:][:cntrl:]]+$', '', 'g'))=k.match_key
                           or octet_length(i.ecosystem)<>char_length(i.ecosystem)
                           or starts_with(lower(i.purl), 'pkg:' || k.match_key || '/'))
                    union
                    select m.component_id from inventory_component_cpe_map m join keys k
                      on k.key_kind='CPE' and m.cpe_id=case when k.key_kind='CPE' then k.match_key::uuid end
                    union
                    select s.component_id from component_vulnerability_states s join changed c using (vulnerability_id)
                    union
                    select f.component_id from findings f join changed c using (vulnerability_id)
                    where f.component_id is not null
                ) affected
                where (?::uuid is null or id>?::uuid) order by id limit 100
                """, UUID.class, release, release, after, after);
    }

    List<UUID> findingScorePage(UUID release, UUID after) {
        return jdbc.queryForList("""
                select f.id from findings f join platform.intelligence_release_route_vulnerabilities r using (vulnerability_id)
                where r.release_id=? and f.intelligence_eligibility='ELIGIBLE' and f.component_id is not null
                  and f.status in ('OPEN','SUPPRESSED') and (?::uuid is null or f.id>?::uuid)
                order by f.id limit 100
                """, UUID.class, release, after, after);
    }

    List<UUID> markRankingRollupPage(UUID tenant, UUID release, UUID after) {
        return jdbc.queryForList("""
                with page as (
                    select vulnerability_id from platform.intelligence_release_route_vulnerabilities
                    where release_id=? and (?::uuid is null or vulnerability_id>?::uuid)
                    order by vulnerability_id limit 100
                ), queued as (
                    insert into inventory_rollup_queue (tenant_id,rollup_kind,subject_id)
                    select ?, 'ORG_CVE', vulnerability_id from page join org_cve_records using (vulnerability_id)
                    order by vulnerability_id
                    on conflict (rollup_kind,subject_id) do update
                        set marked_at=least(inventory_rollup_queue.marked_at,excluded.marked_at)
                ) select vulnerability_id from page order by vulnerability_id
                """, UUID.class, release, after, after, tenant);
    }
}
