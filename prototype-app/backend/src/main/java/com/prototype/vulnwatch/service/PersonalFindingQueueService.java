package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.FindingQueuePreference;
import com.prototype.vulnwatch.domain.PersonalFindingQueue;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FindingQueueDefinitionResponse;
import com.prototype.vulnwatch.dto.FindingQueueUpsertRequest;
import com.prototype.vulnwatch.dto.FindingSummaryResponse;
import com.prototype.vulnwatch.dto.FindingsFilter;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.FindingQueuePreferenceRepository;
import com.prototype.vulnwatch.repo.PersonalFindingQueueRepository;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class PersonalFindingQueueService {

    public static final String KIND_PERSONAL = "PERSONAL";
    public static final String OWNER_TYPE_USER = "USER";
    public static final String PERSONAL_KEY_PREFIX = "personal:";

    private final FindingAnalyticsService findingAnalyticsService;
    private final PersonalFindingQueueRepository personalFindingQueueRepository;
    private final FindingQueuePreferenceRepository findingQueuePreferenceRepository;
    private final AppUserRepository appUserRepository;
    private final RequestActorService requestActorService;
    private final ObjectMapper objectMapper;

    public PersonalFindingQueueService(
            FindingAnalyticsService findingAnalyticsService,
            PersonalFindingQueueRepository personalFindingQueueRepository,
            FindingQueuePreferenceRepository findingQueuePreferenceRepository,
            AppUserRepository appUserRepository,
            RequestActorService requestActorService,
            ObjectMapper objectMapper
    ) {
        this.findingAnalyticsService = findingAnalyticsService;
        this.personalFindingQueueRepository = personalFindingQueueRepository;
        this.findingQueuePreferenceRepository = findingQueuePreferenceRepository;
        this.appUserRepository = appUserRepository;
        this.requestActorService = requestActorService;
        this.objectMapper = objectMapper;
    }

    @Transactional(readOnly = true)
    public List<FindingQueueDefinitionResponse> listQueues(Tenant tenant, String defaultQueueRef) {
        AppUser owner = requireCurrentUser();
        return personalFindingQueueRepository
                .findByTenantIdAndOwnerUserIdOrderByDisplayOrderAscCreatedAtAsc(tenant.getId(), owner.getId()).stream()
                .map(queue -> toPersonalResponse(tenant, queue, Objects.equals(personalQueueRef(queue), defaultQueueRef)))
                .toList();
    }

    @Transactional(readOnly = true)
    public FindingQueueDefinitionResponse getQueue(Tenant tenant, String queueRef, String defaultQueueRef) {
        AppUser owner = requireCurrentUser();
        PersonalFindingQueue personal = requirePersonalQueue(tenant, owner, queueRef);
        return toPersonalResponse(tenant, personal, Objects.equals(personalQueueRef(personal), defaultQueueRef));
    }

    @Transactional
    public FindingQueueDefinitionResponse createQueue(Tenant tenant, FindingQueueUpsertRequest request) {
        AppUser owner = requireCurrentUser();
        FindingsFilter filter = requireFilter(request.filter());
        String title = requireTitle(request.title());
        String queueKey = normalizeQueueKey(title);
        validateUniqueness(tenant, owner, queueKey, title, null);

        PersonalFindingQueue queue = new PersonalFindingQueue();
        queue.setTenant(tenant);
        queue.setOwnerUser(owner);
        queue.setQueueKey(queueKey);
        queue.setTitle(title);
        queue.setDescription(trimToNull(request.description()));
        queue.setFilterJson(writeFilter(filter));
        queue.setDisplayOrder(request.displayOrder() != null ? request.displayOrder() : nextDisplayOrder(tenant, owner));
        queue.setDefault(false);
        queue.touch();
        PersonalFindingQueue saved = personalFindingQueueRepository.save(queue);
        if (Boolean.TRUE.equals(request.setAsDefault())) {
            setDefaultQueueInternal(tenant, owner, personalQueueRef(saved));
        }
        String defaultQueueRef = currentDefaultQueueRef(tenant, owner).orElse(null);
        return toPersonalResponse(tenant, saved, Objects.equals(personalQueueRef(saved), defaultQueueRef));
    }

    @Transactional
    public FindingQueueDefinitionResponse updateQueue(Tenant tenant, String queueRef, FindingQueueUpsertRequest request) {
        AppUser owner = requireCurrentUser();
        PersonalFindingQueue queue = requireEditablePersonalQueue(tenant, owner, queueRef);
        FindingsFilter filter = requireFilter(request.filter());
        String title = requireTitle(request.title());
        String queueKey = normalizeQueueKey(title);
        validateUniqueness(tenant, owner, queueKey, title, queue.getId());

        queue.setTitle(title);
        queue.setQueueKey(queueKey);
        queue.setDescription(trimToNull(request.description()));
        queue.setFilterJson(writeFilter(filter));
        if (request.displayOrder() != null) {
            queue.setDisplayOrder(request.displayOrder());
        }
        queue.touch();
        PersonalFindingQueue saved = personalFindingQueueRepository.save(queue);
        if (Boolean.TRUE.equals(request.setAsDefault())) {
            setDefaultQueueInternal(tenant, owner, personalQueueRef(saved));
        }
        String defaultQueueRef = currentDefaultQueueRef(tenant, owner).orElse(null);
        return toPersonalResponse(tenant, saved, Objects.equals(personalQueueRef(saved), defaultQueueRef));
    }

    @Transactional
    public FindingQueueDefinitionResponse duplicateQueue(Tenant tenant, String queueRef) {
        AppUser owner = requireCurrentUser();
        PersonalFindingQueue source = requireEditablePersonalQueue(tenant, owner, queueRef);
        FindingsFilter filter = readFilter(source.getFilterJson());
        String duplicatedTitle = dedupeTitle(tenant, owner, source.getTitle() + " Copy");
        FindingQueueUpsertRequest request = new FindingQueueUpsertRequest(
                duplicatedTitle,
                source.getDescription(),
                filter,
                nextDisplayOrder(tenant, owner),
                personalQueueRef(source),
                false
        );
        return createQueue(tenant, request);
    }

    @Transactional
    public void deleteQueue(Tenant tenant, String queueRef) {
        AppUser owner = requireCurrentUser();
        PersonalFindingQueue queue = requireEditablePersonalQueue(tenant, owner, queueRef);
        String deletedRef = personalQueueRef(queue);
        personalFindingQueueRepository.delete(queue);
        clearDefaultIfMatches(tenant, owner, deletedRef);
    }

    @Transactional
    public void setDefaultQueue(Tenant tenant, String queueRef) {
        setDefaultQueueInternal(tenant, requireCurrentUser(), queueRef);
    }

    @Transactional(readOnly = true)
    public Optional<String> currentDefaultQueueRef(Tenant tenant) {
        return currentDefaultQueueRef(tenant, requireCurrentUser());
    }

    @Transactional(readOnly = true)
    public FindingsFilter loadQueueFilterForCurrentUser(Tenant tenant, String queueRef) {
        AppUser owner = requireCurrentUser();
        PersonalFindingQueue personal = requirePersonalQueue(tenant, owner, queueRef);
        return readFilter(personal.getFilterJson());
    }

    @Transactional(readOnly = true)
    public String queueTitleForCurrentUser(Tenant tenant, String queueRef) {
        AppUser owner = requireCurrentUser();
        return requirePersonalQueue(tenant, owner, queueRef).getTitle();
    }

    @Transactional(readOnly = true)
    public boolean ownsQueueForCurrentUser(Tenant tenant, String queueRef) {
        AppUser owner = requireCurrentUser();
        try {
            requirePersonalQueue(tenant, owner, queueRef);
            return true;
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private FindingQueueDefinitionResponse toPersonalResponse(Tenant tenant, PersonalFindingQueue queue, boolean isDefault) {
        FindingsFilter filter = readFilter(queue.getFilterJson());
        FindingSummaryResponse summary = findingAnalyticsService.getSummary(tenant, filter);
        return new FindingQueueDefinitionResponse(
                queue.getId(),
                personalQueueRef(queue),
                queue.getTitle(),
                queue.getDescription(),
                KIND_PERSONAL,
                OWNER_TYPE_USER,
                true,
                isDefault,
                findingAnalyticsService.getMatchingCount(tenant, filter),
                filter,
                summary
        );
    }

    private PersonalFindingQueue requireEditablePersonalQueue(Tenant tenant, AppUser owner, String queueRef) {
        return requirePersonalQueue(tenant, owner, queueRef);
    }

    private PersonalFindingQueue requirePersonalQueue(Tenant tenant, AppUser owner, String queueRef) {
        UUID queueId = parsePersonalQueueId(queueRef);
        return personalFindingQueueRepository
                .findByIdAndTenantIdAndOwnerUserId(queueId, tenant.getId(), owner.getId())
                .orElseThrow(() -> new IllegalArgumentException("Finding queue not found: " + queueRef));
    }

    private Optional<String> currentDefaultQueueRef(Tenant tenant, AppUser owner) {
        return findingQueuePreferenceRepository.findByTenantIdAndOwnerUserId(tenant.getId(), owner.getId())
                .map(FindingQueuePreference::getDefaultQueueRef)
                .filter(FindingFilterSpecifications::hasText);
    }

    private void setDefaultQueueInternal(Tenant tenant, AppUser owner, String queueRef) {
        UUID selectedQueueId = null;
        if (queueRef != null && queueRef.toLowerCase(Locale.ROOT).startsWith(PERSONAL_KEY_PREFIX)) {
            selectedQueueId = requirePersonalQueue(tenant, owner, queueRef).getId();
        }
        List<PersonalFindingQueue> queues = personalFindingQueueRepository
                .findByTenantIdAndOwnerUserIdOrderByDisplayOrderAscCreatedAtAsc(tenant.getId(), owner.getId());
        for (PersonalFindingQueue candidate : queues) {
            boolean shouldBeDefault = selectedQueueId != null && candidate.getId().equals(selectedQueueId);
            if (candidate.isDefault() != shouldBeDefault) {
                candidate.setDefault(shouldBeDefault);
                candidate.touch();
                personalFindingQueueRepository.save(candidate);
            }
        }
        FindingQueuePreference preference = findingQueuePreferenceRepository
                .findByTenantIdAndOwnerUserId(tenant.getId(), owner.getId())
                .orElseGet(FindingQueuePreference::new);
        preference.setTenant(tenant);
        preference.setOwnerUser(owner);
        preference.setDefaultQueueRef(queueRef);
        preference.touch();
        findingQueuePreferenceRepository.save(preference);
    }

    private void clearDefaultIfMatches(Tenant tenant, AppUser owner, String queueRef) {
        findingQueuePreferenceRepository.findByTenantIdAndOwnerUserId(tenant.getId(), owner.getId())
                .filter(preference -> Objects.equals(preference.getDefaultQueueRef(), queueRef))
                .ifPresent(findingQueuePreferenceRepository::delete);
    }

    private AppUser requireCurrentUser() {
        RequestActor actor = requestActorService.currentActor();
        return appUserRepository.findByExternalSubject(actor.userId())
                .orElseThrow(() -> new IllegalArgumentException("Authenticated user was not found"));
    }

    private UUID parsePersonalQueueId(String queueRef) {
        String normalized = queueRef == null ? "" : queueRef.trim();
        if (normalized.toLowerCase(Locale.ROOT).startsWith(PERSONAL_KEY_PREFIX)) {
            normalized = normalized.substring(PERSONAL_KEY_PREFIX.length());
        }
        try {
            return UUID.fromString(normalized);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Invalid personal queue id: " + queueRef);
        }
    }

    private String personalQueueRef(PersonalFindingQueue queue) {
        return PERSONAL_KEY_PREFIX + queue.getId();
    }

    private FindingsFilter requireFilter(FindingsFilter filter) {
        if (filter == null) {
            throw new IllegalArgumentException("Queue filter is required");
        }
        return new FindingsFilter(
                filter.severity(),
                filter.status(),
                filter.decisionState(),
                filter.creationSource(),
                filter.matchMethod(),
                filter.vexStatus(),
                filter.vexFreshness(),
                filter.vexProvider(),
                filter.minConfidence(),
                trimToNull(filter.vulnerabilityId()),
                trimToNull(filter.packageName()),
                trimToNull(filter.ecosystem()),
                trimToNull(filter.ownerGroup()),
                trimToNull(filter.assignedTo()),
                filter.unassignedOnly(),
                filter.incidentLinked(),
                trimToNull(filter.dueDateBand()),
                trimToNull(filter.assetName()),
                trimToNull(filter.supportGroup()),
                filter.patchAvailable(),
                trimToNull(filter.suppressedUntilBand()),
                filter.assetType(),
                null,
                null,
                null,
                null,
                null,
                // Saved queues keep the stable owner team (plan §9.7), never a display name.
                filter.ownerTeamId(),
                trimToNull(filter.ownershipStatus())
        );
    }

    private String requireTitle(String title) {
        String normalized = trimToNull(title);
        if (normalized == null) {
            throw new IllegalArgumentException("Queue title is required");
        }
        return normalized;
    }

    private String writeFilter(FindingsFilter filter) {
        try {
            return objectMapper.writeValueAsString(filter);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Unable to persist finding queue filter", ex);
        }
    }

    private FindingsFilter readFilter(String filterJson) {
        try {
            return objectMapper.readValue(filterJson, FindingsFilter.class);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Unable to parse persisted finding queue filter", ex);
        }
    }

    private void validateUniqueness(Tenant tenant, AppUser owner, String queueKey, String title, UUID currentQueueId) {
        List<PersonalFindingQueue> existing = personalFindingQueueRepository
                .findByTenantIdAndOwnerUserIdOrderByDisplayOrderAscCreatedAtAsc(tenant.getId(), owner.getId());
        boolean keyConflict = existing.stream()
                .filter(queue -> currentQueueId == null || !queue.getId().equals(currentQueueId))
                .anyMatch(queue -> queue.getQueueKey().equalsIgnoreCase(queueKey));
        if (keyConflict) {
            throw new IllegalArgumentException("A saved queue with this title already exists");
        }
        boolean titleConflict = existing.stream()
                .filter(queue -> currentQueueId == null || !queue.getId().equals(currentQueueId))
                .anyMatch(queue -> queue.getTitle().equalsIgnoreCase(title));
        if (titleConflict) {
            throw new IllegalArgumentException("A saved queue with this title already exists");
        }
    }

    private int nextDisplayOrder(Tenant tenant, AppUser owner) {
        return personalFindingQueueRepository
                .findByTenantIdAndOwnerUserIdOrderByDisplayOrderAscCreatedAtAsc(tenant.getId(), owner.getId()).stream()
                .map(PersonalFindingQueue::getDisplayOrder)
                .max(Integer::compareTo)
                .orElse(-1) + 1;
    }

    private String dedupeTitle(Tenant tenant, AppUser owner, String baseTitle) {
        List<String> existingTitles = personalFindingQueueRepository
                .findByTenantIdAndOwnerUserIdOrderByDisplayOrderAscCreatedAtAsc(tenant.getId(), owner.getId()).stream()
                .map(queue -> queue.getTitle().toLowerCase(Locale.ROOT))
                .collect(Collectors.toList());
        if (!existingTitles.contains(baseTitle.toLowerCase(Locale.ROOT))) {
            return baseTitle;
        }
        int suffix = 2;
        while (existingTitles.contains((baseTitle + " " + suffix).toLowerCase(Locale.ROOT))) {
            suffix += 1;
        }
        return baseTitle + " " + suffix;
    }

    private String normalizeQueueKey(String title) {
        String normalized = title.trim().toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9]+", "-")
                .replaceAll("^-+", "")
                .replaceAll("-+$", "");
        if (normalized.isBlank()) {
            throw new IllegalArgumentException("Queue title must contain letters or numbers");
        }
        return normalized;
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
