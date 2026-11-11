package com.prototype.vulnwatch.service;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
@DependsOnDatabaseInitialization
@ConditionalOnProperty(name = "app.security.managed-auth.enabled", havingValue = "true")
class ManagedBrowserSessionStore {
    private final JdbcTemplate jdbc;

    ManagedBrowserSessionStore(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    void checkSchema() {
        jdbc.query("""
                select i.user_id, a.browser_hash, a.invite_hash, s.expires_at
                from platform.managed_identities i, platform.managed_login_attempts a, platform.managed_browser_sessions s
                where false
                """, rs -> { });
    }

    void saveAttempt(String stateHash, String browserHash, String verifier, String nonce, String inviteHash) {
        jdbc.update("""
                delete from platform.managed_login_attempts where expires_at <= current_timestamp
                """);
        jdbc.update("""
                insert into platform.managed_login_attempts (state_hash, browser_hash, verifier, nonce, invite_hash, expires_at)
                values (?, ?, ?, ?, ?, current_timestamp + interval '5 minutes')
                """, stateHash, browserHash, verifier, nonce, inviteHash);
    }

    Optional<LoginAttempt> consumeAttempt(String stateHash, String browserHash) {
        return jdbc.query("""
                delete from platform.managed_login_attempts
                where state_hash = ? and browser_hash = ? and expires_at > current_timestamp
                returning verifier, nonce, invite_hash
                """, (rs, row) -> new LoginAttempt(rs.getString("verifier"), rs.getString("nonce"), rs.getString("invite_hash")),
                stateHash, browserHash).stream().findFirst();
    }

    Optional<Instant> createSession(String tokenHash, String previousHash, String issuer, String subject, Instant tokenExpiry) {
        jdbc.update("delete from platform.managed_browser_sessions where expires_at <= current_timestamp");
        return jdbc.query("""
                with created as (
                    insert into platform.managed_browser_sessions (token_hash, identity_id, user_id, expires_at)
                    select ?, i.id, i.user_id, least(?, current_timestamp + interval '30 minutes')
                    from platform.managed_identities i
                    join platform.app_users u on u.id = i.user_id
                    where i.issuer = ? and i.subject = ? and upper(u.status) = 'ACTIVE'
                      and ? > current_timestamp
                    returning expires_at
                ), revoked as (
                    delete from platform.managed_browser_sessions
                    where token_hash = ? and exists (select 1 from created)
                )
                select expires_at from created
                """, (rs, row) -> rs.getTimestamp("expires_at").toInstant(),
                tokenHash, Timestamp.from(tokenExpiry), issuer, subject, Timestamp.from(tokenExpiry), previousHash)
                .stream().findFirst();
    }

    Optional<UUID> findLinkedUser(String issuer, String subject) {
        return jdbc.query("""
                select user_id from platform.managed_identities where issuer = ? and subject = ?
                """, (rs, row) -> rs.getObject("user_id", UUID.class), issuer, subject).stream().findFirst();
    }

    boolean linkNewIdentity(String issuer, String subject, UUID userId) {
        return jdbc.update("""
                insert into platform.managed_identities (issuer, subject, user_id)
                select ?, ?, ? where not exists (select 1 from platform.managed_identities where user_id = ?)
                on conflict do nothing
                """, issuer, subject, userId, userId) == 1;
    }

    Optional<SessionUser> findUser(String tokenHash, String issuer) {
        return jdbc.query("""
                select u.id, u.external_subject, u.email, u.display_name
                from platform.managed_browser_sessions s
                join platform.managed_identities i on i.id = s.identity_id and i.user_id = s.user_id
                join platform.app_users u on u.id = s.user_id
                where s.token_hash = ? and i.issuer = ? and s.expires_at > current_timestamp
                  and upper(u.status) = 'ACTIVE'
                """, (rs, row) -> new SessionUser(rs.getObject("id", UUID.class), rs.getString("external_subject"),
                rs.getString("email"), rs.getString("display_name")), tokenHash, issuer).stream().findFirst();
    }

    void revoke(String tokenHash) {
        jdbc.update("delete from platform.managed_browser_sessions where token_hash = ?", tokenHash);
    }

    record LoginAttempt(String verifier, String nonce, String inviteHash) { }
    record SessionUser(UUID id, String subject, String email, String displayName) { }
}
