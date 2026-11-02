package com.prototype.vulnwatch.service;

import org.springframework.http.HttpStatus;

/** A pipeline-facing ingest failure carrying a stable machine-readable code. */
public class BomIngestException extends RuntimeException {
    private final HttpStatus status;
    private final String code;

    public BomIngestException(HttpStatus status, String code, String message) {
        super(message);
        this.status = status;
        this.code = code;
    }

    public HttpStatus status() {
        return status;
    }

    public String code() {
        return code;
    }
}
