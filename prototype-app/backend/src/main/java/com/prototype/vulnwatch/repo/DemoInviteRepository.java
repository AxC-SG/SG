package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.DemoInvite;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DemoInviteRepository extends JpaRepository<DemoInvite, UUID> {
    Optional<DemoInvite> findByTokenHash(String tokenHash);
    @Query("select i.request.id from DemoInvite i where i.tokenHash = :hash")
    Optional<UUID> findRequestIdByTokenHash(@Param("hash") String hash);
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select i from DemoInvite i where i.tokenHash = :hash")
    Optional<DemoInvite> findByTokenHashForUpdate(@Param("hash") String hash);
    List<DemoInvite> findByRequest_IdOrderByCreatedAtDesc(UUID requestId);
    void deleteByRequest_Id(UUID requestId);
}
