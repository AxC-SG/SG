package com.prototype.vulnwatch.dto;

import java.util.List;
import java.util.UUID;

/** Bounded keyset page; counts intentionally omitted for deep browsing. */
public record CentralCatalogCursorResponse(List<CentralCatalogPageResponse.Record> items,
                                           int size, boolean hasMore,
                                           String nextAfterExternalId, UUID nextAfterId) {}
