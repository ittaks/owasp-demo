package com.demo.owasp.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, String>> handleAccessDenied(AccessDeniedException ex, HttpServletRequest request) {
        String user = request.getUserPrincipal() != null ? request.getUserPrincipal().getName() : "ANONYMOUS";

        String safeUser = com.demo.owasp.security.LogSanitizer.sanitize(user);
        String safeUri = com.demo.owasp.security.LogSanitizer.sanitize(request.getRequestURI());

        // Dodajemo i sanitizaciju Query Stringa (npr. ?search=...)
        String queryString = request.getQueryString();
        String safeQuery = queryString != null ? com.demo.owasp.security.LogSanitizer.sanitize(queryString) : "";

        log.warn("SECURITY VIOLATION: User '{}' attempted unauthorized access to path: {}{} [{}]",
                safeUser, safeUri, (queryString != null ? "?" + safeQuery : ""), request.getMethod());

        Map<String, String> response = new HashMap<>();
        response.put("error", "Access Denied");
        response.put("message", "You do not have permission to execute this operation.");
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }
    @ExceptionHandler(org.springframework.http.converter.HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, String>> handleHttpMessageNotReadableException(
            org.springframework.http.converter.HttpMessageNotReadableException ex) {

        // SIGURNA PRAKSA: Logiramo samo kratku poruku, izbjegavamo ispis cijelog stack trace-a u log datoteke!
        log.warn("BAD REQUEST: Primljen neispravan JSON format tijela zahtjeva. Detalj: {}", ex.getMostSpecificCause().getMessage());

        Map<String, String> response = new java.util.HashMap<>();
        response.put("error", "Bad Request");
        response.put("message", "The provided JSON request body is malformed and cannot be parsed.");

        return ResponseEntity.status(org.springframework.http.HttpStatus.BAD_REQUEST).body(response);
    }
    // =========================================================================
    // OWASP A09:2025 ZAŠTITA - Logiranje sigurnosnih incidenata (CWE-778)
    // =========================================================================
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Map<String, String>> handleBadCredentials(BadCredentialsException ex) {

        // Eksplicitno bilježimo neuspjelu autentifikaciju na nivou WARN.
        // SIEM sustavi prate ove logove kako bi detektirali Brute-Force napade.
        // Strogo pazimo da ne ispišemo poslanu lozinku u zapisnik (Mitigacija CWE-532).
        log.warn("SECURITY INCIDENT: Authentication failed. Bad credentials provided.");

        Map<String, String> response = new HashMap<>();
        response.put("error", "Unauthorized");
        response.put("message", "The username or password provided is incorrect.");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<Map<String, String>> handleResourceNotFound(ResourceNotFoundException ex) {
        Map<String, String> response = new HashMap<>();
        response.put("error", "Not Found");
        response.put("message", ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleIllegalArgumentException(IllegalArgumentException ex) {
        Map<String, String> response = new HashMap<>();
        response.put("error", "Bad Request");
        response.put("message", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> handleGenericException(Exception ex) {
        log.error("Internal server failure", ex);

        Map<String, String> response = new HashMap<>();
        response.put("error", "Internal Server Error");
        response.put("message", "An unexpected error occurred. Please contact system administrators.");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }

    /**
     * Globalni upravitelj iznimkama na razini aplikacije.
     * Proširen je metodom za presretanje MethodArgumentNotValidException kako bi se klijentu
     * vratile isključivo sanirane i jasne poruke o neuspjeloj validaciji unosa.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidationExceptions(MethodArgumentNotValidException ex) {
        Map<String, Object> response = new HashMap<>();
        Map<String, String> errors = new HashMap<>();

        ex.getBindingResult().getFieldErrors().forEach((error) -> {
            errors.put(error.getField(), error.getDefaultMessage());
        });

        // Logiramo pokušaj slanja nevalidnih unosa radi ranog otkrivanja fuzzing skripti
        log.info("Validation failed for request. Fields in error: {}", errors.keySet());

        response.put("error", "Bad Request");
        response.put("validationErrors", errors);

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }
}