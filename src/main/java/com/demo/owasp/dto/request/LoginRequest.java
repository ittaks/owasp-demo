package com.demo.owasp.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class LoginRequest {
    /*
     * OWASP A07:2025 ZAŠTITA
     * Sprječava prazne zahtjeve koji mogu
     * poslužiti za automatizirano ispitivanje sustava.
     */
    @NotBlank
    private String username;
    @NotBlank
    private String password;
}
