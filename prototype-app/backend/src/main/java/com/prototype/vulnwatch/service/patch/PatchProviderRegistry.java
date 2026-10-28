package com.prototype.vulnwatch.service.patch;

import com.prototype.vulnwatch.domain.PatchProviderType;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import static org.springframework.http.HttpStatus.NOT_FOUND;

/** Every registered {@link PatchProvider}, keyed by tool. */
@Component
public class PatchProviderRegistry {

    private final Map<PatchProviderType, PatchProvider> providers;

    public PatchProviderRegistry(List<PatchProvider> providers) {
        Map<PatchProviderType, PatchProvider> resolved = new EnumMap<>(PatchProviderType.class);
        for (PatchProvider provider : providers) {
            if (resolved.put(provider.type(), provider) != null) {
                throw new IllegalStateException("Two PatchProvider beans claim " + provider.type());
            }
        }
        this.providers = Map.copyOf(resolved);
    }

    public Optional<PatchProvider> find(PatchProviderType type) {
        return Optional.ofNullable(providers.get(type));
    }

    public PatchProvider require(PatchProviderType type) {
        return find(type).orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "Unsupported patch provider"));
    }

    public List<PatchProviderType> types() {
        return providers.keySet().stream().sorted().toList();
    }
}
