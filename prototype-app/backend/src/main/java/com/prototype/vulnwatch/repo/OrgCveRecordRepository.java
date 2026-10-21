package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.OrgCveRecord;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;

public interface OrgCveRecordRepository extends JpaRepository<OrgCveRecord, UUID> {
    interface ExposureSummaryRow {
        long getReviewQueueCount();
        Long getApplicableCount();
        Long getImpactedCount();
        Long getUnderInvestigationCount();
        Long getResolvedCount();
    }

    Optional<OrgCveRecord> findByVulnerability(Vulnerability vulnerability);
    Optional<OrgCveRecord> findByVulnerability_Id(UUID vulnerabilityId);

    List<OrgCveRecord> findBySuppressedByRuleIdIsNull();

    @org.springframework.data.jpa.repository.Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    List<OrgCveRecord> findBySuppressedByRuleIdIsNullOrderById();

    long countBySuppressedByRuleId(UUID suppressedByRuleId);

    List<OrgCveRecord> findBySuppressedByRuleId(UUID suppressedByRuleId);

    List<OrgCveRecord> findByVulnerability_IdIn(Collection<UUID> vulnerabilityIds);

    @Query("""
            select distinct o.tenant.id
            from OrgCveRecord o
            where o.vulnerability.id in :vulnerabilityIds
            """)
    Set<UUID> findDistinctTenantIdsByVulnerabilityIds(@Param("vulnerabilityIds") Collection<UUID> vulnerabilityIds);

    @Query("""
            select max(o.lastEvaluatedAt)
            from OrgCveRecord o
            where o.tenant = :tenant
            """)
    java.time.Instant findLatestLastEvaluatedAt(@Param("tenant") Tenant tenant);

    long countByApplicabilityState(ApplicabilityState applicabilityState);

    long countByImpactedTrue();

    @Query("select o from OrgCveRecord o where o.tenant.id = :tenantId and o.vulnerability = :vulnerability")
    Optional<OrgCveRecord> findByTenantIdAndVulnerability(@Param("tenantId") UUID tenantId,
                                                           @Param("vulnerability") Vulnerability vulnerability);

    @EntityGraph(attributePaths = {"vulnerability"})
    @Query(
            value = """
                    select o
                    from OrgCveRecord o
                    where o.tenant = :tenant
                      and (:inKev is null or o.inKev = :inKev)
                      and (
                        :includeAll = true
                        or o.applicabilityState = com.prototype.vulnwatch.domain.ApplicabilityState.APPLICABLE
                      )
                    order by
                      case when o.impacted = true then 1 else 0 end desc,
                      case when o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNDER_INVESTIGATION then 1 else 0 end desc,
                      case when o.inKev = true then 1 else 0 end desc,
                      coalesce(o.epssScore, 0.0) desc,
                      coalesce(o.cvssScore, 0.0) desc,
                      o.externalId asc
                    """,
            countQuery = """
                    select count(o.id)
                    from OrgCveRecord o
                    where o.tenant = :tenant
                      and (:inKev is null or o.inKev = :inKev)
                      and (
                        :includeAll = true
                        or o.applicabilityState = com.prototype.vulnwatch.domain.ApplicabilityState.APPLICABLE
                      )
                    """
    )
    Page<OrgCveRecord> findExposurePage(
            @Param("tenant") Tenant tenant,
            @Param("inKev") Boolean inKev,
            @Param("includeAll") boolean includeAll,
            Pageable pageable
    );

    @EntityGraph(attributePaths = {"vulnerability"})
    @Query(
            value = """
                    select o
                    from OrgCveRecord o
                    where o.tenant = :tenant
                      and (:inKev is null or o.inKev = :inKev)
                      and (
                        :includeAll = true
                        or o.applicabilityState = com.prototype.vulnwatch.domain.ApplicabilityState.APPLICABLE
                      )
                      and o.externalId = :externalId
                    order by
                      case when o.impacted = true then 1 else 0 end desc,
                      case when o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNDER_INVESTIGATION then 1 else 0 end desc,
                      case when o.inKev = true then 1 else 0 end desc,
                      coalesce(o.epssScore, 0.0) desc,
                      coalesce(o.cvssScore, 0.0) desc,
                      o.externalId asc
                    """,
            countQuery = """
                    select count(o.id)
                    from OrgCveRecord o
                    where o.tenant = :tenant
                      and (:inKev is null or o.inKev = :inKev)
                      and (
                        :includeAll = true
                        or o.applicabilityState = com.prototype.vulnwatch.domain.ApplicabilityState.APPLICABLE
                      )
                      and o.externalId = :externalId
                    """
    )
    Page<OrgCveRecord> findExposurePageByExternalId(
            @Param("tenant") Tenant tenant,
            @Param("externalId") String externalId,
            @Param("inKev") Boolean inKev,
            @Param("includeAll") boolean includeAll,
            Pageable pageable
    );

    @EntityGraph(attributePaths = {"vulnerability"})
    @Query(
            value = """
                    select o
                    from OrgCveRecord o
                    join o.vulnerability v
                    where o.tenant = :tenant
                      and (:inKev is null or o.inKev = :inKev)
                      and (
                        :includeAll = true
                        or o.applicabilityState = com.prototype.vulnwatch.domain.ApplicabilityState.APPLICABLE
                      )
                      and (
                        upper(o.externalId) like concat('%', :queryUpper, '%')
                        or upper(o.severity) like concat('%', :queryUpper, '%')
                        or upper(coalesce(v.title, '')) like concat('%', :queryUpper, '%')
                        or upper(coalesce(v.descriptionSnippet, '')) like concat('%', :queryUpper, '%')
                      )
                    order by
                      case when o.impacted = true then 1 else 0 end desc,
                      case when o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNDER_INVESTIGATION then 1 else 0 end desc,
                      case when o.inKev = true then 1 else 0 end desc,
                      coalesce(o.epssScore, 0.0) desc,
                      coalesce(o.cvssScore, 0.0) desc,
                      o.externalId asc
                    """,
            countQuery = """
                    select count(o.id)
                    from OrgCveRecord o
                    join o.vulnerability v
                    where o.tenant = :tenant
                      and (:inKev is null or o.inKev = :inKev)
                      and (
                        :includeAll = true
                        or o.applicabilityState = com.prototype.vulnwatch.domain.ApplicabilityState.APPLICABLE
                      )
                      and (
                        upper(o.externalId) like concat('%', :queryUpper, '%')
                        or upper(o.severity) like concat('%', :queryUpper, '%')
                        or upper(coalesce(v.title, '')) like concat('%', :queryUpper, '%')
                        or upper(coalesce(v.descriptionSnippet, '')) like concat('%', :queryUpper, '%')
                      )
                    """
    )
    Page<OrgCveRecord> findExposurePage(
            @Param("tenant") Tenant tenant,
            @Param("queryUpper") String queryUpper,
            @Param("inKev") Boolean inKev,
            @Param("includeAll") boolean includeAll,
            Pageable pageable
    );

    @EntityGraph(attributePaths = {"vulnerability"})
    @Query(
            value = """
                    select o
                    from OrgCveRecord o
                    where o.tenant = :tenant
                      and (:inKev is null or o.inKev = :inKev)
                      and upper(coalesce(o.severity, 'UNKNOWN')) = :severity
                      and (
                        :includeAll = true
                        or o.applicabilityState = com.prototype.vulnwatch.domain.ApplicabilityState.APPLICABLE
                      )
                    order by
                      case when o.impacted = true then 1 else 0 end desc,
                      case when o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNDER_INVESTIGATION then 1 else 0 end desc,
                      case when o.inKev = true then 1 else 0 end desc,
                      coalesce(o.epssScore, 0.0) desc,
                      coalesce(o.cvssScore, 0.0) desc,
                      o.externalId asc
                    """,
            countQuery = """
                    select count(o.id)
                    from OrgCveRecord o
                    where o.tenant = :tenant
                      and (:inKev is null or o.inKev = :inKev)
                      and upper(coalesce(o.severity, 'UNKNOWN')) = :severity
                      and (
                        :includeAll = true
                        or o.applicabilityState = com.prototype.vulnwatch.domain.ApplicabilityState.APPLICABLE
                      )
                    """
    )
    Page<OrgCveRecord> findExposurePageBySeverity(
            @Param("tenant") Tenant tenant,
            @Param("severity") String severity,
            @Param("inKev") Boolean inKev,
            @Param("includeAll") boolean includeAll,
            Pageable pageable
    );

    @EntityGraph(attributePaths = {"vulnerability"})
    @Query(
            value = """
                    select o
                    from OrgCveRecord o
                    where o.tenant = :tenant
                      and (:inKev is null or o.inKev = :inKev)
                      and (
                        o.inKev = true
                        or coalesce(o.epssScore, 0.0) >= 0.9
                      )
                      and (:includeAll = true or o.applicabilityState = com.prototype.vulnwatch.domain.ApplicabilityState.APPLICABLE)
                    order by
                      case when o.impacted = true then 1 else 0 end desc,
                      case when o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNDER_INVESTIGATION then 1 else 0 end desc,
                      case when o.inKev = true then 1 else 0 end desc,
                      coalesce(o.epssScore, 0.0) desc,
                      coalesce(o.cvssScore, 0.0) desc,
                      o.externalId asc
                    """,
            countQuery = """
                    select count(o.id)
                    from OrgCveRecord o
                    where o.tenant = :tenant
                      and (:inKev is null or o.inKev = :inKev)
                      and (
                        o.inKev = true
                        or coalesce(o.epssScore, 0.0) >= 0.9
                      )
                      and (:includeAll = true or o.applicabilityState = com.prototype.vulnwatch.domain.ApplicabilityState.APPLICABLE)
                    """
    )
    Page<OrgCveRecord> findExposurePageExploitOnly(
            @Param("tenant") Tenant tenant,
            @Param("inKev") Boolean inKev,
            @Param("includeAll") boolean includeAll,
            Pageable pageable
    );

    @EntityGraph(attributePaths = {"vulnerability"})
    @Query(
            value = """
                    select o
                    from OrgCveRecord o
                    join o.vulnerability v
                    where o.tenant = :tenant
                      and (:inKev is null or o.inKev = :inKev)
                      and (:sourceFilter = false or o.vulnerability.id in :sourceIds or (:kevSource = true and o.inKev = true))
                      and (:hasFindings is null or (:hasFindings = true and exists (select f.id from Finding f where f.tenant = :tenant and f.vulnerability = o.vulnerability))
                           or (:hasFindings = false and not exists (select f.id from Finding f where f.tenant = :tenant and f.vulnerability = o.vulnerability)))
                      and (:externalId is null or o.externalId = :externalId)
                      and (:severity is null or upper(coalesce(o.severity, 'UNKNOWN')) = :severity)
                      and (:createdSinceSet = false or o.createdAt >= :createdSince)
                      and (
                        :exploitOnly is null
                        or :exploitOnly = false
                        or o.inKev = true
                        or coalesce(o.epssScore, 0.0) >= 0.9
                      )
                      and (
                        (:softwareIdentityId is null and :softwarePattern is null)
                        or o.vulnerability.id in (
                          select distinct cvs.vulnerability.id
                          from ComponentVulnerabilityState cvs
                          join cvs.component ic
                          left join ic.softwareIdentity sid
                          where cvs.tenant = :tenant
                            and (
                              (:softwareIdentityId is not null and sid.id = :softwareIdentityId)
                              or
                              (
                                :softwareIdentityId is null
                                and
                                (
                              upper(coalesce(ic.packageName, '')) like :softwarePattern
                              or upper(coalesce(ic.normalizedName, '')) like :softwarePattern
                              or upper(coalesce(sid.displayName, '')) like :softwarePattern
                              or upper(coalesce(sid.canonicalKey, '')) like :softwarePattern
                              or upper(coalesce(sid.product, '')) like :softwarePattern
                              or upper(coalesce(sid.vendor, '')) like :softwarePattern
                                )
                              )
                            )
                        )
                      )
                      and (
                        :includeAll = true
                        or o.applicabilityState = com.prototype.vulnwatch.domain.ApplicabilityState.APPLICABLE
                      )
                      and (:impactedOnly = false or o.matchedAssetCount > 0)
                      and (
                        :queryPattern is null
                        or upper(o.externalId) like :queryPattern
                        or upper(o.severity) like :queryPattern
                        or upper(coalesce(v.title, '')) like :queryPattern
                        or upper(coalesce(v.descriptionSnippet, '')) like :queryPattern
                      )
                    order by
                      case when o.impacted = true then 1 else 0 end desc,
                      case when o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNDER_INVESTIGATION then 1 else 0 end desc,
                      case when o.inKev = true then 1 else 0 end desc,
                      coalesce(o.epssScore, 0.0) desc,
                      coalesce(o.cvssScore, 0.0) desc,
                      o.externalId asc
                    """,
            countQuery = """
                    select count(o.id)
                    from OrgCveRecord o
                    join o.vulnerability v
                    where o.tenant = :tenant
                      and (:inKev is null or o.inKev = :inKev)
                      and (:sourceFilter = false or o.vulnerability.id in :sourceIds or (:kevSource = true and o.inKev = true))
                      and (:hasFindings is null or (:hasFindings = true and exists (select f.id from Finding f where f.tenant = :tenant and f.vulnerability = o.vulnerability))
                           or (:hasFindings = false and not exists (select f.id from Finding f where f.tenant = :tenant and f.vulnerability = o.vulnerability)))
                      and (:externalId is null or o.externalId = :externalId)
                      and (:severity is null or upper(coalesce(o.severity, 'UNKNOWN')) = :severity)
                      and (:createdSinceSet = false or o.createdAt >= :createdSince)
                      and (
                        :exploitOnly is null
                        or :exploitOnly = false
                        or o.inKev = true
                        or coalesce(o.epssScore, 0.0) >= 0.9
                      )
                      and (
                        (:softwareIdentityId is null and :softwarePattern is null)
                        or o.vulnerability.id in (
                          select distinct cvs.vulnerability.id
                          from ComponentVulnerabilityState cvs
                          join cvs.component ic
                          left join ic.softwareIdentity sid
                          where cvs.tenant = :tenant
                            and (
                              (:softwareIdentityId is not null and sid.id = :softwareIdentityId)
                              or
                              (
                                :softwareIdentityId is null
                                and
                                (
                              upper(coalesce(ic.packageName, '')) like :softwarePattern
                              or upper(coalesce(ic.normalizedName, '')) like :softwarePattern
                              or upper(coalesce(sid.displayName, '')) like :softwarePattern
                              or upper(coalesce(sid.canonicalKey, '')) like :softwarePattern
                              or upper(coalesce(sid.product, '')) like :softwarePattern
                              or upper(coalesce(sid.vendor, '')) like :softwarePattern
                                )
                              )
                            )
                        )
                      )
                      and (
                        :includeAll = true
                        or o.applicabilityState = com.prototype.vulnwatch.domain.ApplicabilityState.APPLICABLE
                      )
                      and (:impactedOnly = false or o.matchedAssetCount > 0)
                      and (
                        :queryPattern is null
                        or upper(o.externalId) like :queryPattern
                        or upper(o.severity) like :queryPattern
                        or upper(coalesce(v.title, '')) like :queryPattern
                        or upper(coalesce(v.descriptionSnippet, '')) like :queryPattern
                      )
                    """
    )
    Page<OrgCveRecord> findExposurePageFiltered(
            @Param("tenant") Tenant tenant,
            @Param("queryPattern") String queryPattern,
            @Param("externalId") String externalId,
            @Param("inKev") Boolean inKev,
            @Param("severity") String severity,
            @Param("exploitOnly") Boolean exploitOnly,
            @Param("createdSinceSet") boolean createdSinceSet,
            @Param("createdSince") java.time.Instant createdSince,
            @Param("softwareIdentityId") UUID softwareIdentityId,
            @Param("softwarePattern") String softwarePattern,
            @Param("includeAll") boolean includeAll,
            @Param("impactedOnly") boolean impactedOnly,
            @Param("sourceFilter") boolean sourceFilter,
            @Param("sourceIds") List<UUID> sourceIds,
            @Param("kevSource") boolean kevSource,
            @Param("hasFindings") Boolean hasFindings,
            Pageable pageable
    );

    @EntityGraph(attributePaths = {"vulnerability"})
    @Query(
            value = """
                    select o
                    from OrgCveRecord o
                    join o.vulnerability v
                    where o.tenant = :tenant
                      and (:inKev is null or o.inKev = :inKev)
                      and (:sourceFilter = false or o.vulnerability.id in :sourceIds or (:kevSource = true and o.inKev = true))
                      and (:hasFindings is null or (:hasFindings = true and exists (select f.id from Finding f where f.tenant = :tenant and f.vulnerability = o.vulnerability))
                           or (:hasFindings = false and not exists (select f.id from Finding f where f.tenant = :tenant and f.vulnerability = o.vulnerability)))
                      and (:externalId is null or o.externalId = :externalId)
                      and (:severity is null or upper(coalesce(o.severity, 'UNKNOWN')) = :severity)
                      and (:createdSinceSet = false or o.createdAt >= :createdSince)
                      and (
                        :exploitOnly is null
                        or :exploitOnly = false
                        or o.inKev = true
                        or coalesce(o.epssScore, 0.0) >= 0.9
                      )
                      and (
                        (:softwareIdentityId is null and :softwarePattern is null)
                        or o.vulnerability.id in (
                          select distinct cvs.vulnerability.id
                          from ComponentVulnerabilityState cvs
                          join cvs.component ic
                          left join ic.softwareIdentity sid
                          where cvs.tenant = :tenant
                            and (
                              (:softwareIdentityId is not null and sid.id = :softwareIdentityId)
                              or
                              (
                                :softwareIdentityId is null
                                and
                                (
                              upper(coalesce(ic.packageName, '')) like :softwarePattern
                              or upper(coalesce(ic.normalizedName, '')) like :softwarePattern
                              or upper(coalesce(sid.displayName, '')) like :softwarePattern
                              or upper(coalesce(sid.canonicalKey, '')) like :softwarePattern
                              or upper(coalesce(sid.product, '')) like :softwarePattern
                              or upper(coalesce(sid.vendor, '')) like :softwarePattern
                                )
                              )
                            )
                        )
                      )
                      and (
                        :includeAll = true
                        or o.applicabilityState = com.prototype.vulnwatch.domain.ApplicabilityState.APPLICABLE
                      )
                      and (:impactedOnly = false or o.matchedAssetCount > 0)
                      and (
                        :queryPattern is null
                        or upper(o.externalId) like :queryPattern
                        or upper(o.severity) like :queryPattern
                        or upper(coalesce(v.title, '')) like :queryPattern
                        or upper(coalesce(v.descriptionSnippet, '')) like :queryPattern
                      )
                    order by
                      case when o.impacted = true then 1 else 0 end desc,
                      case when o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNDER_INVESTIGATION then 1 else 0 end desc,
                      case when o.inKev = true then 1 else 0 end desc,
                      coalesce(o.epssScore, 0.0) desc,
                      coalesce(o.cvssScore, 0.0) desc,
                      o.externalId asc
                    """,
            countQuery = """
                    select count(o.id)
                    from OrgCveRecord o
                    join o.vulnerability v
                    where o.tenant = :tenant
                      and (:inKev is null or o.inKev = :inKev)
                      and (:sourceFilter = false or o.vulnerability.id in :sourceIds or (:kevSource = true and o.inKev = true))
                      and (:hasFindings is null or (:hasFindings = true and exists (select f.id from Finding f where f.tenant = :tenant and f.vulnerability = o.vulnerability))
                           or (:hasFindings = false and not exists (select f.id from Finding f where f.tenant = :tenant and f.vulnerability = o.vulnerability)))
                      and (:externalId is null or o.externalId = :externalId)
                      and (:severity is null or upper(coalesce(o.severity, 'UNKNOWN')) = :severity)
                      and (:createdSinceSet = false or o.createdAt >= :createdSince)
                      and (
                        :exploitOnly is null
                        or :exploitOnly = false
                        or o.inKev = true
                        or coalesce(o.epssScore, 0.0) >= 0.9
                      )
                      and (
                        (:softwareIdentityId is null and :softwarePattern is null)
                        or o.vulnerability.id in (
                          select distinct cvs.vulnerability.id
                          from ComponentVulnerabilityState cvs
                          join cvs.component ic
                          left join ic.softwareIdentity sid
                          where cvs.tenant = :tenant
                            and (
                              (:softwareIdentityId is not null and sid.id = :softwareIdentityId)
                              or
                              (
                                :softwareIdentityId is null
                                and
                                (
                              upper(coalesce(ic.packageName, '')) like :softwarePattern
                              or upper(coalesce(ic.normalizedName, '')) like :softwarePattern
                              or upper(coalesce(sid.displayName, '')) like :softwarePattern
                              or upper(coalesce(sid.canonicalKey, '')) like :softwarePattern
                              or upper(coalesce(sid.product, '')) like :softwarePattern
                              or upper(coalesce(sid.vendor, '')) like :softwarePattern
                                )
                              )
                            )
                        )
                      )
                      and (
                        :includeAll = true
                        or o.applicabilityState = com.prototype.vulnwatch.domain.ApplicabilityState.APPLICABLE
                      )
                      and (:impactedOnly = false or o.matchedAssetCount > 0)
                      and (
                        :queryPattern is null
                        or upper(o.externalId) like :queryPattern
                        or upper(o.severity) like :queryPattern
                        or upper(coalesce(v.title, '')) like :queryPattern
                        or upper(coalesce(v.descriptionSnippet, '')) like :queryPattern
                      )
                    """
    )
    Page<OrgCveRecord> findExposurePageFilteredBroadSoftware(
            @Param("tenant") Tenant tenant,
            @Param("queryPattern") String queryPattern,
            @Param("externalId") String externalId,
            @Param("inKev") Boolean inKev,
            @Param("severity") String severity,
            @Param("exploitOnly") Boolean exploitOnly,
            @Param("createdSinceSet") boolean createdSinceSet,
            @Param("createdSince") java.time.Instant createdSince,
            @Param("softwareIdentityId") UUID softwareIdentityId,
            @Param("softwarePattern") String softwarePattern,
            @Param("includeAll") boolean includeAll,
            @Param("impactedOnly") boolean impactedOnly,
            @Param("sourceFilter") boolean sourceFilter,
            @Param("sourceIds") List<UUID> sourceIds,
            @Param("kevSource") boolean kevSource,
            @Param("hasFindings") Boolean hasFindings,
            Pageable pageable
    );

    @EntityGraph(attributePaths = {"vulnerability"})
    @Query(
            value = """
                    select o
                    from OrgCveRecord o
                    join o.vulnerability v
                    where o.tenant = :tenant
                      and o.vulnerability.id in :vulnIds
                      and (:inKev is null or o.inKev = :inKev)
                      and (:severity is null or upper(coalesce(o.severity, 'UNKNOWN')) = :severity)
                      and (
                        :includeAll = true
                        or o.applicabilityState = com.prototype.vulnwatch.domain.ApplicabilityState.APPLICABLE
                      )
                      and (:impactedOnly = false or o.matchedAssetCount > 0)
                      and (
                        :queryPattern is null
                        or upper(o.externalId) like :queryPattern
                        or upper(coalesce(v.title, '')) like :queryPattern
                        or upper(coalesce(v.descriptionSnippet, '')) like :queryPattern
                      )
                    order by
                      case when o.impacted = true then 1 else 0 end desc,
                      case when o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNDER_INVESTIGATION then 1 else 0 end desc,
                      case when o.inKev = true then 1 else 0 end desc,
                      coalesce(o.epssScore, 0.0) desc,
                      coalesce(o.cvssScore, 0.0) desc,
                      o.externalId asc
                    """,
            countQuery = """
                    select count(o.id)
                    from OrgCveRecord o
                    join o.vulnerability v
                    where o.tenant = :tenant
                      and o.vulnerability.id in :vulnIds
                      and (:inKev is null or o.inKev = :inKev)
                      and (:severity is null or upper(coalesce(o.severity, 'UNKNOWN')) = :severity)
                      and (
                        :includeAll = true
                        or o.applicabilityState = com.prototype.vulnwatch.domain.ApplicabilityState.APPLICABLE
                      )
                      and (:impactedOnly = false or o.matchedAssetCount > 0)
                      and (
                        :queryPattern is null
                        or upper(o.externalId) like :queryPattern
                        or upper(coalesce(v.title, '')) like :queryPattern
                        or upper(coalesce(v.descriptionSnippet, '')) like :queryPattern
                      )
                    """
    )
    Page<OrgCveRecord> findExposurePageBySourceVulnIds(
            @Param("tenant") Tenant tenant,
            @Param("vulnIds") Collection<UUID> vulnIds,
            @Param("inKev") Boolean inKev,
            @Param("severity") String severity,
            @Param("includeAll") boolean includeAll,
            @Param("impactedOnly") boolean impactedOnly,
            @Param("queryPattern") String queryPattern,
            Pageable pageable
    );

    @Query("""
            select
              count(o) as reviewQueueCount,
              count(o) as applicableCount,
              sum(case when o.impacted = true then 1 else 0 end) as impactedCount,
              sum(case when o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNDER_INVESTIGATION then 1 else 0 end) as underInvestigationCount,
              sum(case when o.impactState in (
                    com.prototype.vulnwatch.domain.ImpactState.FIXED,
                    com.prototype.vulnwatch.domain.ImpactState.NOT_IMPACTED
                  ) then 1 else 0 end) as resolvedCount
            from OrgCveRecord o
            where o.tenant = :tenant
              and o.applicabilityState = com.prototype.vulnwatch.domain.ApplicabilityState.APPLICABLE
            """)
    Optional<ExposureSummaryRow> summarizeExposureCounts(@Param("tenant") Tenant tenant);

    default Optional<OrgCveRecord> findByTenantIdAndVulnerability(Long tenantId, Vulnerability vulnerability) {
        return findByTenantIdAndVulnerability(toTenantUuid(tenantId), vulnerability);
    }

    private static UUID toTenantUuid(Long tenantId) {
        return tenantId == null ? null : new UUID(0L, tenantId);
    }
}
