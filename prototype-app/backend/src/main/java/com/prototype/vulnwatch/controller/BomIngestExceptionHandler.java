package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.service.BomIngestException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Maps pipeline-facing ingest failures onto the API's usual error shape, keeping their code. */
// Ahead of ApiExceptionHandler, whose catch-all would otherwise turn these into a 500.
@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice(assignableTypes = {BomIngestController.class, BomIngestKeyController.class})
public class BomIngestExceptionHandler {

    @ExceptionHandler(BomIngestException.class)
    public ResponseEntity<Map<String, Object>> handle(BomIngestException ex) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("timestamp", Instant.now());
        payload.put("code", ex.code());
        payload.put("error", ex.getMessage());
        return ResponseEntity.status(ex.status()).body(payload);
    }
}
