package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.PlatformIntelligenceProgressResponse;
import com.prototype.vulnwatch.dto.NvdObservedGapsResponse;
import com.prototype.vulnwatch.dto.NvdBaselinePlanResponse;
import com.prototype.vulnwatch.dto.NvdObservedScopesResponse;
import com.prototype.vulnwatch.dto.NvdObservedIdComparisonResponse;
import com.prototype.vulnwatch.service.PlatformIntelligenceProgressService;
import com.prototype.vulnwatch.service.vulningestion.NvdObservedGapsService;
import com.prototype.vulnwatch.service.vulningestion.NvdObservedIdComparisonService;
import java.time.Instant;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/platform/intelligence/progress")
@PreAuthorize("hasRole('PLATFORM_OWNER')")
public class PlatformIntelligenceProgressController {
    private final PlatformIntelligenceProgressService progress;
    private final NvdObservedGapsService gaps;
    private final NvdObservedIdComparisonService comparison;
    public PlatformIntelligenceProgressController(PlatformIntelligenceProgressService progress,
                                                 NvdObservedGapsService gaps,
                                                 NvdObservedIdComparisonService comparison) {
        this.progress = progress;
        this.gaps = gaps;
        this.comparison = comparison;
    }
    @GetMapping public PlatformIntelligenceProgressResponse get() { return progress.progress(); }
    @GetMapping("/nvd-observed-scopes")
    public NvdObservedScopesResponse nvdObservedScopes(@RequestParam(required = false) String afterFeedKey) {
        return gaps.scopes(afterFeedKey);
    }
    @GetMapping("/nvd-observed-gaps")
    public NvdObservedGapsResponse nvdObservedGaps(@RequestParam String feedKey,
                                                    @RequestParam Instant from, @RequestParam Instant to) {
        return gaps.inspect(feedKey, from, to);
    }
    @GetMapping("/nvd-baseline-plan")
    public NvdBaselinePlanResponse nvdBaselinePlan(@RequestParam String feedKey,
                                                    @RequestParam Instant from, @RequestParam Instant to) {
        return gaps.plan(feedKey, from, to);
    }
    @GetMapping("/nvd-observed-id-comparison")
    public NvdObservedIdComparisonResponse nvdObservedIdComparison(
            @RequestParam UUID firstRunId, @RequestParam UUID secondRunId,
            @RequestParam String feedKey, @RequestParam Instant from, @RequestParam Instant to) {
        return comparison.compare(firstRunId, secondRunId, feedKey, from, to);
    }
}
