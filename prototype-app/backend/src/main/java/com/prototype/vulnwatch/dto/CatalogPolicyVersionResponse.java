package com.prototype.vulnwatch.dto;

import java.time.Instant;

public record CatalogPolicyVersionResponse(long version, String sha256, Instant createdAt, CatalogPolicy policy) {}
