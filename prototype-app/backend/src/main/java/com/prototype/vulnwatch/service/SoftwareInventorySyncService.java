package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.SoftwareInventoryItem;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.SoftwareInventoryItemRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class SoftwareInventorySyncService {

    private final SoftwareInventoryItemRepository softwareInventoryItemRepository;
    private final TenantWorkRunner tenantWorkRunner;

    public SoftwareInventorySyncService(
            SoftwareInventoryItemRepository softwareInventoryItemRepository,
            TenantWorkRunner tenantWorkRunner
    ) {
        this.softwareInventoryItemRepository = softwareInventoryItemRepository;
        this.tenantWorkRunner = tenantWorkRunner;
    }

    public int syncFromInventoryDelta(Tenant tenant, Collection<InventoryComponent> components, Instant observedAt) {
        if (tenant == null || tenant.getId() == null || components == null || components.isEmpty()) {
            return 0;
        }
        return tenantWorkRunner.runScoped(tenant, () -> syncScoped(tenant, components, observedAt));
    }

    private int syncScoped(Tenant tenant, Collection<InventoryComponent> components, Instant observedAt) {

        List<InventoryComponent> scopedComponents = components.stream()
                .filter(component -> component != null
                        && component.getId() != null
                        && component.getTenant() != null
                        && tenant.getId().equals(component.getTenant().getId()))
                .sorted(Comparator.comparing(InventoryComponent::getId))
                .toList();
        if (scopedComponents.isEmpty()) {
            return 0;
        }

        Set<UUID> componentIds = scopedComponents.stream()
                .map(InventoryComponent::getId)
                .collect(java.util.stream.Collectors.toCollection(java.util.LinkedHashSet::new));
        Map<UUID, SoftwareInventoryItem> existingByComponentId = new HashMap<>();
        softwareInventoryItemRepository.findByComponent_IdIn(componentIds).forEach(item -> {
            if (item.getComponent() != null && item.getComponent().getId() != null) {
                existingByComponentId.put(item.getComponent().getId(), item);
            }
        });

        Instant syncTime = observedAt == null ? Instant.now() : observedAt;
        List<SoftwareInventoryItem> toSave = new ArrayList<>();
        for (InventoryComponent component : scopedComponents) {
            SoftwareInventoryItem item = existingByComponentId.get(component.getId());
            boolean created = false;
            if (item == null) {
                item = new SoftwareInventoryItem();
                item.setTenant(tenant);
                item.setComponent(component);
                item.setFirstSeenAt(component.getIngestedAt() == null ? syncTime : component.getIngestedAt());
                created = true;
            }

            Instant lastObservedAt = component.getLastObservedAt() == null ? syncTime : component.getLastObservedAt();
            boolean changed = created;
            changed |= setIfChanged(item.getAsset(), component.getAsset(), item::setAsset);
            changed |= setIfChanged(item.getEcosystem(), normalize(component.getEcosystem()), item::setEcosystem);
            changed |= setIfChanged(item.getPackageName(), normalize(component.getPackageName()), item::setPackageName);
            changed |= setIfChanged(item.getVersion(), defaultString(component.getVersion(), "unknown"), item::setVersion);
            changed |= setIfChanged(item.getPurl(), defaultString(component.getPurl(), ""), item::setPurl);
            changed |= setIfChanged(item.getComponentStatus(), component.getComponentStatus(), item::setComponentStatus);
            changed |= setIfChanged(item.getLastObservedAt(), lastObservedAt, item::setLastObservedAt);

            if (!changed) {
                continue;
            }

            item.setSyncedAt(syncTime);
            item.touch();
            toSave.add(item);
        }

        if (!toSave.isEmpty()) {
            softwareInventoryItemRepository.saveAll(toSave);
        }
        return toSave.size();
    }

    private String normalize(String value) {
        if (value == null || value.isBlank()) {
            return "unknown";
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }

    private String defaultString(String value, String fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        return value;
    }

    private <T> boolean setIfChanged(T current, T next, java.util.function.Consumer<T> setter) {
        if (Objects.equals(current, next)) {
            return false;
        }
        setter.accept(next);
        return true;
    }
}
