package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.AppUserGlobalRole;
import com.prototype.vulnwatch.repo.AppUserGlobalRoleRepository;
import com.prototype.vulnwatch.repo.AppUserRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AppUserGlobalRoleService {

    private final AppUserGlobalRoleRepository globalRoleRepository;
    private final AppUserRepository userRepository;
    private final EntityManager entityManager;

    public AppUserGlobalRoleService(
            AppUserGlobalRoleRepository globalRoleRepository,
            AppUserRepository userRepository,
            EntityManager entityManager
    ) {
        this.globalRoleRepository = globalRoleRepository;
        this.userRepository = userRepository;
        this.entityManager = entityManager;
    }

    @Transactional(readOnly = true)
    public Set<String> rolesForUser(UUID userId) {
        LinkedHashSet<String> roles = new LinkedHashSet<>();
        if (userId == null) {
            return roles;
        }
        globalRoleRepository.findByUser_IdOrderByCreatedAtAsc(userId)
                .forEach(role -> roles.add(normalizeRole(role.getRole())));
        userRepository.findById(userId)
                .filter(AppUser::isPlatformOwner)
                .ifPresent(user -> roles.add("PLATFORM_OWNER"));
        return roles;
    }

    @Transactional(readOnly = true)
    public Map<UUID, Set<String>> rolesByUserIds(Collection<UUID> userIds) {
        Map<UUID, Set<String>> result = new LinkedHashMap<>();
        if (userIds == null || userIds.isEmpty()) {
            return result;
        }
        globalRoleRepository.findByUser_IdIn(userIds).forEach(role -> result
                .computeIfAbsent(role.getUser().getId(), ignored -> new LinkedHashSet<>())
                .add(normalizeRole(role.getRole())));
        userRepository.findAllById(userIds).forEach(user -> {
            if (user.isPlatformOwner()) {
                result.computeIfAbsent(user.getId(), ignored -> new LinkedHashSet<>()).add("PLATFORM_OWNER");
            }
        });
        return result;
    }

    @Transactional
    public void ensureRole(AppUser user, String role) {
        if (user == null || user.getId() == null) {
            return;
        }
        user = lockCurrentUser(user);
        String normalizedRole = normalizeRole(role);
        if (globalRoleRepository.findByUser_IdAndRole(user.getId(), normalizedRole).isPresent()) {
            syncCompatibilityFlag(user, normalizedRole, true);
            return;
        }
        AppUserGlobalRole globalRole = new AppUserGlobalRole();
        globalRole.setUser(user);
        globalRole.setRole(normalizedRole);
        globalRole.setCreatedAt(Instant.now());
        globalRoleRepository.save(globalRole);
        syncCompatibilityFlag(user, normalizedRole, true);
    }

    @Transactional
    public void revokeRole(AppUser user, String role) {
        if (user == null || user.getId() == null) {
            return;
        }
        user = lockCurrentUser(user);
        String normalizedRole = normalizeRole(role);
        // Historical aliases must not survive removal of the same effective authority.
        globalRoleRepository.deleteAll(globalRoleRepository.findByUser_IdOrderByCreatedAtAsc(user.getId()).stream()
                .filter(existing -> normalizedRole.equals(normalizeRole(existing.getRole())))
                .toList());
        syncCompatibilityFlag(user, normalizedRole, false);
    }

    private AppUser lockCurrentUser(AppUser user) {
        AppUser current = userRepository.findByIdForUpdate(user.getId())
                .orElseThrow(() -> new IllegalStateException("User is not registered"));
        // A caller may already have loaded the entity before acquiring its row lock.
        entityManager.refresh(current, LockModeType.PESSIMISTIC_WRITE);
        return current;
    }

    private void syncCompatibilityFlag(AppUser user, String normalizedRole, boolean granted) {
        if (!"PLATFORM_OWNER".equals(normalizedRole)) {
            return;
        }
        if (granted) {
            if (!user.isPlatformOwner()) {
                user.setPlatformOwner(true);
                user.setUpdatedAt(Instant.now());
                userRepository.save(user);
            }
            return;
        }
        boolean stillPresent = globalRoleRepository.findByUser_IdAndRole(user.getId(), normalizedRole).isPresent();
        if (!stillPresent && user.isPlatformOwner()) {
            user.setPlatformOwner(false);
            user.setUpdatedAt(Instant.now());
            userRepository.save(user);
        }
    }

    private String normalizeRole(String role) {
        if (role == null || role.isBlank()) {
            throw new IllegalArgumentException("role is required");
        }
        return TenantRolePolicy.canonicalRole(role);
    }
}
