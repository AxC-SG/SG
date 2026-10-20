package com.prototype.vulnwatch.service;

import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/** Kept as a rejection boundary for any stale direct caller. */
@Service
public class FixDemoDataSeeder {
    public List<Map<String, Object>> generateDemoFixes() {
        throw new ResponseStatusException(HttpStatus.GONE, "FIX_INTELLIGENCE_UNAVAILABLE");
    }
}
