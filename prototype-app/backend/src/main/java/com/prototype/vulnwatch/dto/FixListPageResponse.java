package com.prototype.vulnwatch.dto;

import java.util.List;

public record FixListPageResponse(
        List<FixListItemResponse> items,
        int page,
        int size,
        long totalItems,
        int totalPages
) {}
