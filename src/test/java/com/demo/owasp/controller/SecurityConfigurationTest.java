package com.demo.owasp.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hibernate.validator.internal.util.Contracts.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

/**
 * Integracijski testovi za OWASP A02:2025 — Security Misconfiguration
 * Verificira ispravnost sigurnosnih postavki okruženja, rukovanja iznimkama i HTTP zaglavlja.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SecurityConfigurationTest {

    @Autowired
    private MockMvc mockMvc;

    // =========================================================================
    // OWASP A02:2025 — Ranjivost: Izloženost osjetljivih Actuator endpointa
    // =========================================================================
    @Test
    @DisplayName("Osjetljivi Actuator endpointi (/env) moraju biti nedostupni javnosti")
    void sensitiveActuatorEndpoints_shouldBeProtected() throws Exception {
        // Izloženost /actuator/env može otkriti lozinke iz baze i privatne ključeve.
        // Očekujemo status 401 Unauthorized ili 403 Forbidden za neautentificirane zahtjeve.
        mockMvc.perform(get("/actuator/env"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Samo osnovni zdravstveni endpoint (/health) smije biti javno dostupan")
    void publicActuatorHealth_shouldBeAccessible() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }

    // =========================================================================
    // OWASP A02:2025 — Ranjivost: Curenje informacija kroz Stack Trace (Information Disclosure)
    // =========================================================================
    @Test
    @DisplayName("Globalni Exception Handler mora sakriti stacktrace i vratiti generičku poruku (Prevencija A02)")
    void globalExceptionHandler_shouldNotLeakStackTrace() throws Exception {
        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("")) // Šaljemo namjerno neispravan, prazan body kako bismo izazvali iznimku
                // Budući da GlobalExceptionHandler mapira neočekivane pogreške na status 500, očekujemo 500
                .andExpect(status().isInternalServerError())
                .andExpect(result -> {
                    String responseBody = result.getResponse().getContentAsString();

                    // Ključne provjere za OWASP A02 - Podaci ne smiju procuriti u tijelo HTTP odgovora!
                    assertFalse(responseBody.contains("Exception"), "HTTP odgovor ne smije sadržavati riječ 'Exception'!");
                    assertFalse(responseBody.contains("at com.demo.owasp"), "HTTP odgovor je procurio interni stack trace aplikacije!");
                    assertTrue(responseBody.contains("An unexpected error occurred"), "Klijent mora dobiti generičku, sigurnu poruku o pogrešci.");
                });
    }
    // =========================================================================
    // OWASP A02:2025 — Ranjivost: Nedostatak sigurnosnih HTTP zaglavlja
    // =========================================================================
    @Test
    @DisplayName("Svaki odgovor aplikacije mora sadržavati osnovna sigurnosna HTTP zaglavlja")
    void httpSecurityHeaders_shouldBePresent() throws Exception {
        // Provjeravamo da Spring Security automatski ubrizgava obrambena zaglavlja u odgovore
        mockMvc.perform(get("/auth/login")) // Može bilo koji endpoint
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"));
    }
}