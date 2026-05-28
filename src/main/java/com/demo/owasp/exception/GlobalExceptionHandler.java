package com.demo.owasp.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, String>> handleAccessDenied(AccessDeniedException ex, HttpServletRequest request) { // [cite: 83]
        String user = request.getUserPrincipal() != null ? request.getUserPrincipal().getName() : "ANONYMOUS"; // [cite: 83, 84]
        log.warn("SECURITY VIOLATION: User '{}' attempted unauthorized access to path: {} [{}]",
                user, request.getRequestURI(), request.getMethod()); // [cite: 84, 85]

        Map<String, String> response = new HashMap<>();
        response.put("error", "Access Denied");
        response.put("message", "You do not have permission to execute this operation."); // [cite: 85]
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response); //
    }

    // OWASP A02 FIX: Centralizirano presretanje neuspjelih prijava - vraća se točan 401 status umjesto greške 500
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Map<String, String>> handleBadCredentials(BadCredentialsException ex) {
        Map<String, String> response = new HashMap<>();
        response.put("error", "Unauthorized");
        response.put("message", "The username or password provided is incorrect.");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> handleGenericException(Exception ex) { //
        log.error("Internal server failure", ex); //

        Map<String, String> response = new HashMap<>(); //
        response.put("error", "Internal Server Error"); // [cite: 87]
        response.put("message", "An unexpected error occurred. Please contact system administrators."); // [cite: 87]
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response); // [cite: 88]
    }
}