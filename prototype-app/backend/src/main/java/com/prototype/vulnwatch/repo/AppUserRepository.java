package com.prototype.vulnwatch.repo;

import jakarta.persistence.LockModeType;
import com.prototype.vulnwatch.domain.AppUser;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AppUserRepository extends JpaRepository<AppUser, UUID> {
    Optional<AppUser> findByExternalSubject(String externalSubject);
    Optional<AppUser> findByEmailIgnoreCase(String email);
    Optional<AppUser> findByPasswordSetupTokenHash(String passwordSetupTokenHash);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from AppUser u where u.externalSubject = :subject")
    Optional<AppUser> findByExternalSubjectForUpdate(@Param("subject") String subject);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from AppUser u where lower(u.email) = lower(:email)")
    Optional<AppUser> findByEmailIgnoreCaseForUpdate(@Param("email") String email);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from AppUser u where u.passwordSetupTokenHash = :tokenHash")
    Optional<AppUser> findByPasswordSetupTokenHashForUpdate(@Param("tokenHash") String tokenHash);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from AppUser u where u.id = :id")
    Optional<AppUser> findByIdForUpdate(@Param("id") UUID id);
}
