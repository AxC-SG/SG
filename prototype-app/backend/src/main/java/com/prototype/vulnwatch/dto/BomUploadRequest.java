package com.prototype.vulnwatch.dto;

import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BomSourceCompleteness;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.util.BomInputLimits;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.UUID;

public record BomUploadRequest(
        @NotNull BomType bomType,
        @NotNull AssetType assetType,
        @NotBlank @Size(max = 255) String assetName,
        @NotBlank @Size(max = 255) String assetIdentifier,
        @Size(max = 255) String supplier,
        @NotBlank @Size(max = 255) String filename,
        @Min(1) @Max(BomInputLimits.MAX_BOM_BYTES) int size,
        @NotBlank @Pattern(regexp = "[A-Za-z0-9+/]{43}=") String sha256,
        UUID sourceId,
        BomSourceCompleteness completeness
) {
    public BomUploadRequest {
        if (completeness == null) {
            completeness = BomSourceCompleteness.PARTIAL;
        }
    }
}
