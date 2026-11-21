package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.util.IdentityUtil;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
        // EPSS normalization also writes source provenance. Only a reviewed
        // score-only candidate can classify those derived rows as ranking work.
        boolean epssOnly = Boolean.TRUE.equals(jdbc.queryForObject("""
                select exists(
                    select 1 from platform.intelligence_releases l
                    where l.id=? and l.candidate_id is not null
                      and exists(select 1 from platform.intelligence_candidate_records c
                                 where c.candidate_id=l.candidate_id and c.validation='VALID')
                      and not exists (
                          select 1 from platform.intelligence_candidate_records c
                          where c.candidate_id=l.candidate_id and c.validation='VALID' and not (
                            c.source_system='epss' and (
                              (c.kind='METADATA' and c.payload - array['epss_score','epss_updated_at']='{}'::jsonb)
                              or (c.kind='OBSERVATION' and
                                jsonb_strip_nulls(c.payload) - array['externalId','sourceSystem','sourceRecordId',
                                    'epssScore','lastModifiedAt']='{}'::jsonb)
                            )
                          )
                      )
                )
                """, Boolean.class, release));
        String[] rankingFields = epssOnly
                ? new String[] {"epss_score","epss_updated_at","updated_at","summary_updated_at","last_modified_at","source_count"}
                : new String[] {"epss_score","epss_updated_at","updated_at","summary_updated_at"};
        String mode = jdbc.queryForObject("""
                select case
                    when count(*)=0 then null
                    when bool_and(table_schema='platform' and case
                        when table_name in ('vulnerabilities','vulnerability_intel_summary') then
                            previous_value is not null and new_value is not null
                            and previous_value - ?::text[] = new_value - ?::text[]
                        when table_name in ('vulnerability_intel_observations','vulnerability_intel_relations') then
                            ? and coalesce(previous_value->>'source_system','epss')='epss'
                              and coalesce(new_value->>'source_system','epss')='epss'
                        when table_name='vulnerability_intel_summary_sources' then ?
                        else false end) then 'RANKING'
                    when not bool_and(table_schema='platform'
                        and (previous_value is not null or new_value is not null)
                        and (table_name='vulnerabilities' or (
                            table_name in ('vulnerability_targets','vulnerability_rules','vulnerability_config_expr',
                                'vulnerability_intel_observations','vulnerability_intel_summary',
                                'vulnerability_intel_summary_sources','vex_assertions')
                            and (previous_value is null or coalesce(previous_value->>'vulnerability_id','')
                                ~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$')
                            and (new_value is null or coalesce(new_value->>'vulnerability_id','')
                                ~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$')))) then null
                    else 'APPLICABILITY' end
                from platform.intelligence_release_changes where release_id=?
                """, String.class, rankingFields, rankingFields, epssOnly, epssOnly, release);
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
                    ('COORD', case when t.target_type in ('COORD','ADVISORY_PACKAGE')
                        then t.normalized_target_key end),
                    ('IDENTITY', t.software_identity_id)) key(kind,value)
                where nullif(key.value,'') is not null
                """, release, release, release);
    }

    record ComponentPage(List<UUID> examined, List<UUID> affected) {}
    private record Component(UUID id, boolean direct, String ecosystem, String name, String purl) {}
    private record MatchKey(String kind, String value) {}

    ComponentPage componentPage(UUID release, UUID after) {
        List<Component> components = jdbc.query("""
                with keys as (select key_kind, match_key from platform.intelligence_release_route_targets where release_id=?),
                changed as (select vulnerability_id from platform.intelligence_release_route_vulnerabilities where release_id=?),
                ecosystems as (
                    select split_part(match_key, ':', 1) as name, bool_or(key_kind='ECOSYSTEM') as legacy
                    from keys where key_kind in ('COORD','ECOSYSTEM') group by 1
                ),
                candidates as (
                    select i.id, false as direct from inventory_components i where exists (
                      select 1 from keys k where k.key_kind='PURL' and (k.match_key=i.normalized_purl
                          or lower(regexp_replace(i.purl, '^[[:space:][:cntrl:]]+|[[:space:][:cntrl:]]+$', '', 'g'))=k.match_key
                          or octet_length(i.purl)<>char_length(i.purl)))
                    union all
                    select i.id, true from inventory_components i join keys k
                      on k.key_kind='IDENTITY' and i.software_identity_id=case when k.key_kind='IDENTITY' then k.match_key::uuid end
                    union all
                    select i.id, e.legacy from inventory_components i join ecosystems e
                      on (
                          lower(regexp_replace(i.ecosystem, '^[[:space:][:cntrl:]]+|[[:space:][:cntrl:]]+$', '', 'g'))
                              =e.name
                          or octet_length(i.ecosystem)<>char_length(i.ecosystem)
                          or (starts_with(i.purl,'pkg:') and (
                              lower(regexp_replace(regexp_replace(substr(i.purl,5), '[/@?#].*$', ''),
                                  '^[[:space:][:cntrl:]]+|[[:space:][:cntrl:]]+$', '', 'g'))=e.name
                              or octet_length(i.purl)<>char_length(i.purl))))
                    union all
                    select m.component_id, true from inventory_component_cpe_map m join keys k
                      on k.key_kind='CPE' and m.cpe_id=case when k.key_kind='CPE' then k.match_key::uuid end
                    union all
                    select s.component_id, true from component_vulnerability_states s join changed c using (vulnerability_id)
                    union all
                    select f.component_id, true from findings f join changed c using (vulnerability_id)
                    where f.component_id is not null
                ), page as (
                    select id, bool_or(direct) as direct from candidates
                    where (?::uuid is null or id>?::uuid) group by id order by id limit 100
                ) select page.id,page.direct,i.ecosystem,i.package_name,i.purl from page
                  join inventory_components i using (id) order by page.id
                """, (rs, index) -> new Component(rs.getObject(1, UUID.class), rs.getBoolean(2),
                rs.getString(3), rs.getString(4), rs.getString(5)), release, release, after, after);

        Map<UUID, Set<MatchKey>> componentKeys = new HashMap<>();
        Set<String> lookups = new HashSet<>();
        for (Component component : components) {
            if (component.direct()) continue;
            Set<MatchKey> matches = new HashSet<>();
            for (String coord : IdentityUtil.correlationCoordKeys(component.ecosystem(), component.name(), component.purl())) {
                matches.add(new MatchKey("COORD", coord));
                lookups.add(coord);
            }
            String purl = IdentityUtil.normalizePurl(component.purl());
            if (!purl.isBlank()) {
                matches.add(new MatchKey("PURL", purl));
                lookups.add(purl);
            }
            componentKeys.put(component.id(), matches);
        }
        Set<MatchKey> applicableKeys = findMatchingKeys(release, lookups);
        return new ComponentPage(components.stream().map(Component::id).toList(),
                components.stream().filter(component -> component.direct()
                        || componentKeys.get(component.id()).stream().anyMatch(applicableKeys::contains))
                        .map(Component::id).toList());
    }

    private Set<MatchKey> findMatchingKeys(UUID release, Set<String> lookups) {
        if (lookups.isEmpty()) return Set.of();
        return new HashSet<>(jdbc.query(connection -> {
            var statement = connection.prepareStatement("""
                    select key_kind,match_key from platform.intelligence_release_route_targets
                    where release_id=? and key_kind in ('COORD','PURL') and match_key=any(?)
                    """);
            statement.setObject(1, release);
            statement.setArray(2, connection.createArrayOf("text", lookups.toArray()));
            return statement;
        }, (rs, index) -> new MatchKey(rs.getString(1), rs.getString(2))));
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
