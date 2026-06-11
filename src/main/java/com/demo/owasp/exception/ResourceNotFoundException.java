package com.demo.owasp.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * OWASP A05 Obrana - Specifična iznimka za nepostojeće resurse.
 * Anotacija @ResponseStatus automatski mapira ovu iznimku u HTTP 404 Not Found,
 * čime sprječavamo curenje 500 grešaka prema klijentu.
 */
@ResponseStatus(HttpStatus.NOT_FOUND)
public class ResourceNotFoundException extends RuntimeException {
    public ResourceNotFoundException(String message) {
        super(message);
    }
}