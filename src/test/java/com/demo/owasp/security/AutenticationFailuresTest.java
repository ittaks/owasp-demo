package com.demo.owasp.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuthenticationFailuresTest {

    @Autowired
    private MockMvc mockMvc;

    private final ObjectMapper objectMapper = new ObjectMapper();

    // =========================================================================
    // TEST 1: Obrana od Credential Stuffing-a i ispravan HTTP status (OWASP A02/A07 Fix)
    // =========================================================================
    @Test
    @DisplayName("Sustav mora odbiti prijavu s neispravnim vjerodajnicama i vratiti točan 401 status")
    void shouldReturn401WhenCredentialsAreInvalid() throws Exception {
        // Simuliramo login zahtjev s pogrešnom lozinkom (Credential Stuffing / Password Spraying pokušaj)
        String loginJson = """
                {
                    "username": "postojećiKorisnik",
                    "password": "pogresnaLozinka123"
                }
                """;

        // Pretpostavljamo da ti se login endpoint nalazi na /auth/login ili /users/login
        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson)
                        .with(csrf()))
                .andExpect(status().isUnauthorized()) // Očekujemo 401 Unauthorized
                .andExpect(jsonPath("$.error").value("Unauthorized"))
                .andExpect(jsonPath("$.message").value("The username or password provided is incorrect."));
    }

    // =========================================================================
    // TEST 2: Provjera SecurityFilterChain-a (Sprječavanje javnog pristupa zaštićenim rutama)
    // =========================================================================
    @Test
    @DisplayName("Zaštićeni endpointi moraju odbiti anonimne zahtjeve bez validnog tokena")
    void shouldRejectAnonymousUserFromProtectedRoutes() throws Exception {
        // Pokušavamo dohvatiti zadatke bez postavljanja .with(user(...)) konteksta (simulacija anonimnog napadača)
        mockMvc.perform(get("/tasks")
                        .with(csrf()))
                .andExpect(status().isUnauthorized()); // Ili isForbidden() ovisno o tvojoj Spring Security konfiguraciji za anonimne korisnike
    }

    // =========================================================================
    // TEST 3: Validacija JWT Bearer Tokena (Obrana od manipulacije tokenima)
    // =========================================================================
    @Test
    @DisplayName("API mora eksplicitno odbiti zahtjeve koji šalju nevažeći ili modificirani JWT token")
    void shouldRejectInvalidJwtToken() throws Exception {
        // Šaljemo strukturalno neispravan token
        String maliciousJwt = "Bearer potpuno.nevažeći.token";

        mockMvc.perform(get("/tasks")
                        .header("Authorization", maliciousJwt)
                        .with(csrf()))
                // Očekujemo status 401 jer ga filter sada elegantno vraća kroz response!
                .andExpect(status().isUnauthorized());
    }
}