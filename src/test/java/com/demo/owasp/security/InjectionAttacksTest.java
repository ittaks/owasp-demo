package com.demo.owasp.security;

import com.demo.owasp.dto.request.LoginRequest;
import com.demo.owasp.dto.request.TaskRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integracijski testovi za OWASP A05:2025 — Injection
 * Validacija zaštite od SQL, XSS i URL injekcija uz pravilno rukovanje sigurnosnim kontekstom.
 */
@SpringBootTest
@AutoConfigureMockMvc
class InjectionAttacksTest {

    @Autowired
    private MockMvc mockMvc;

    private final ObjectMapper objectMapper = new ObjectMapper();

    // =========================================================================
    // 1. TEST: SQL Injection u Login Body-ju (Javna ruta, ne treba auth)
    // =========================================================================
    @Test
    @DisplayName("SQL Injection u login formi ne smije zaobići autentifikaciju")
    void loginPayload_shouldHandleSqlInjectionSafely() throws Exception {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername("admin' OR '1'='1");
        loginRequest.setPassword("lozinka");

        mockMvc.perform(post("/auth/login")
                        .with(csrf()) // Sprječava CSRF blokadu ako je aktivna
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized()); // Očekujemo 401 jer korisnik ne postoji
    }

    // =========================================================================
    // 2. TEST: SQL Injection kroz URL parametar (@PathVariable)
    // =========================================================================
    @Test
    @DisplayName("SQL Injection kroz URL ID parametar ne smije ugroziti bazu podataka")
    void pathVariable_shouldHandleSqlWithParametrization() throws Exception {
        String maliciousId = "1' OR 1=1 --";

        mockMvc.perform(get("/tasks/" + maliciousId)
                        .with(user("testKorisnik").roles("USER")) // Autentifikacija kroz MockMvc post-processor
                        .with(csrf()))
                .andExpect(status().is4xxClientError()); // Očekujemo 400 ili 404, ali ne 401 ili 500 SQL Error
    }

    // =========================================================================
    // 3. TEST: Stored XSS u TaskRequest-u (Validacija)
    // =========================================================================
    @Test
    @DisplayName("Validacija @Pattern u TaskRequest-u mora blokirati XSS Script oznake")
    void taskPayload_shouldRejectXssInjection() throws Exception {
        TaskRequest taskRequest = new TaskRequest();
        taskRequest.setTitle("Dobar naslov");
        taskRequest.setDescription("<script>alert('XSS_Napad')</script>");

        mockMvc.perform(post("/tasks")
                        .with(user("testKorisnik").roles("USER")) // Zaobilazimo JWT filter postavljanjem valjanog objekta
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(taskRequest)))
                .andExpect(status().isBadRequest()); // Sada će uspješno okinuti 400 Bad Request zbog @Valid!
    }
}