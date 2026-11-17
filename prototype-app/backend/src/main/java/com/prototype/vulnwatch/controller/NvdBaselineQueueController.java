package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.service.vulningestion.NvdBaselineQueueService;
import java.time.Instant;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/ingestion/nvd-baseline")
@PreAuthorize("hasRole('PLATFORM_OWNER')")
public class NvdBaselineQueueController {
    private final NvdBaselineQueueService queue;

    public NvdBaselineQueueController(NvdBaselineQueueService queue) {
        this.queue = queue;
    }

    @PostMapping("/next")
    public NvdBaselineQueueService.NextWindow queueNext(@RequestParam Instant from, @RequestParam Instant to) {
        return queue.queueNext(from, to);
    }
}
