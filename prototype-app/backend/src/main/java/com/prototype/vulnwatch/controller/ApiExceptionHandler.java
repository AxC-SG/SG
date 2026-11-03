package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.service.QuotaExceededException;
import com.prototype.vulnwatch.service.DemoAccessException;
import com.prototype.vulnwatch.service.CryptoSuppressionPolicyException;
import com.prototype.vulnwatch.security.PublicRateLimitException;
import jakarta.persistence.EntityNotFoundException;
import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.PessimisticLockingFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

@RestControllerAdvice
public class ApiExceptionHandler {
    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(EntityNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Map<String, Object> handleNotFound(EntityNotFoundException ex) {
        return error("NOT_FOUND", ex.getMessage());
    }

    @ExceptionHandler(CryptoSuppressionPolicyException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public Map<String, Object> handleCryptoSuppressionPolicy(CryptoSuppressionPolicyException ex) {
        return error(ex.getReasonCode(), ex.getMessage());
    }

    @ExceptionHandler(NoResourceFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Map<String, Object> handleMissingRoute(NoResourceFoundException ex) {
        return error("NOT_FOUND", "Resource not found");
    }

    @ExceptionHandler(NoHandlerFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Map<String, Object> handleMissingHandler(NoHandlerFoundException ex) {
        return error("NOT_FOUND", "Resource not found");
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, Object> handleValidation(MethodArgumentNotValidException ex) {
        Map<String, String> fields = new LinkedHashMap<>();
        ex.getBindingResult().getFieldErrors()
                .forEach(fieldError -> fields.put(fieldError.getField(), fieldError.getDefaultMessage()));
        Map<String, Object> payload = error("VALIDATION_ERROR", "Validation failed");
        payload.put("fields", fields);
        return payload;
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    @ResponseStatus(HttpStatus.METHOD_NOT_ALLOWED)
    public Map<String, Object> handleMethodNotAllowed(HttpRequestMethodNotSupportedException ex) {
        return error("METHOD_NOT_ALLOWED", ex.getMessage() == null ? "Request method is not supported" : ex.getMessage());
    }

    @ExceptionHandler({IllegalArgumentException.class, IllegalStateException.class, HttpMessageNotReadableException.class})
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, Object> handleBadRequest(Exception ex) {
        log.warn("Bad request while handling API call: {}", ex.getMessage(), ex);
        return error("BAD_REQUEST", ex.getMessage() == null ? "Invalid request" : ex.getMessage());
    }

    @ExceptionHandler(IOException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, Object> handleIo(IOException ex) {
        String message = ex.getMessage() == null ? "" : ex.getMessage();
        if (message.toLowerCase().contains("already in progress")) {
            log.warn("I/O error while handling API request: {}", message);
        } else {
            log.warn("I/O error while handling API request: {}", message, ex);
        }
        return error("INGESTION_ERROR", ex.getMessage() == null ? "Failed to process ingestion request" : ex.getMessage());
    }

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<Map<String, Object>> handleResponseStatus(ResponseStatusException ex) {
        HttpStatus status = HttpStatus.resolve(ex.getStatusCode().value());
        if (status == null) {
            status = HttpStatus.BAD_REQUEST;
        }
        String code = switch (status) {
            case NOT_FOUND -> "NOT_FOUND";
            case UNAUTHORIZED -> "UNAUTHORIZED";
            case FORBIDDEN -> "FORBIDDEN";
            case CONFLICT -> "CONFLICT";
            case TOO_MANY_REQUESTS -> "TOO_MANY_REQUESTS";
            default -> "BAD_REQUEST";
        };
        String message = ex.getReason() == null || ex.getReason().isBlank()
                ? status.getReasonPhrase()
                : ex.getReason();
        log.warn("Response status exception while handling API request: {}", message);
        return ResponseEntity.status(status).body(error(code, message));
    }

    @ExceptionHandler({CannotAcquireLockException.class, PessimisticLockingFailureException.class})
    @ResponseStatus(HttpStatus.CONFLICT)
    public Map<String, Object> handleLockContention(Exception ex) {
        log.warn("Lock contention while handling API request: {}", ex.getMessage(), ex);
        return error("RESOURCE_BUSY", "Another ingestion is in progress for this asset. Please retry shortly.");
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, Object> handleDataIntegrityViolation(DataIntegrityViolationException ex) {
        log.warn("Data integrity violation while handling API request: {}", ex.getMessage(), ex);
        String message = ex.getMessage() == null ? "" : ex.getMessage();
        if (message.contains("uk_aws_discovery_targets_config_account")) {
            return error("BAD_REQUEST", "AWS account target already exists for this connector.");
        }
        return error("BAD_REQUEST", "Request conflicts with existing data.");
    }

    @ExceptionHandler({AccessDeniedException.class, AuthorizationDeniedException.class, SecurityException.class})
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public Map<String, Object> handleAccessDenied(Exception ex) {
        log.warn("Access denied while handling API request: {}", ex.getMessage());
        return error("PERMISSION_DENIED", "Permission denied");
    }

    @ExceptionHandler(QuotaExceededException.class)
    @ResponseStatus(HttpStatus.TOO_MANY_REQUESTS)
    public Map<String, Object> handleQuotaExceeded(QuotaExceededException ex) {
        log.warn("Tenant quota exceeded while handling API request: {}", ex.getMessage());
        Map<String, Object> payload = error(ex.getQuotaCode(), ex.getMessage());
        payload.put("quotaCode", ex.getQuotaCode());
        if (ex.getRetryAfterSeconds() != null) {
            payload.put("retryAfterSeconds", ex.getRetryAfterSeconds());
        }
        return payload;
    }

    @ExceptionHandler(DemoAccessException.class)
    public ResponseEntity<Map<String, Object>> handleDemoAccess(DemoAccessException ex) {
        log.warn("Demo access boundary rejected API request: {}", ex.getMessage());
        return ResponseEntity.status(ex.getStatus()).body(error(ex.getCode(), ex.getMessage()));
    }

    @ExceptionHandler(PublicRateLimitException.class)
    public ResponseEntity<Map<String, Object>> handlePublicRateLimit(PublicRateLimitException ex) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header("Retry-After", Long.toString(ex.getRetryAfterSeconds()))
                .body(error("RATE_LIMITED", ex.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Map<String, Object> handleGeneric(Exception ex) {
        log.error("Unhandled API error", ex);
        return error("INTERNAL_ERROR", "Internal server error");
    }

    private Map<String, Object> error(String code, String message) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("timestamp", Instant.now());
        payload.put("code", code);
        payload.put("error", message);
        return payload;
    }
}
