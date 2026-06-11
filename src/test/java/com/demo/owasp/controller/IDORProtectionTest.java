package com.demo.owasp.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integracijski testovi za OWASP A01:2025 — IDOR zaštita.
 * Verificira da korisnik ne može pristupiti, izmijeniti ni obrisati
 * resurse koji mu ne pripadaju, čak i uz valjani JWT token.
 */
@SpringBootTest
@AutoConfigureMockMvc
class IDORProtectionTest {

    @Autowired
    private MockMvc mockMvc;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private String tokenUserA;
    private String tokenUserB;
    private String taskIdOwnedByUserA;

    /**
     * Prije svakog testa: registriraj dva korisnika, prijavi ih i UserA kreira zadatak.
     * Koristimo timestamp u username-u da izbjegnemo konflikte između testova.
     */
    @BeforeEach
    void setUp() throws Exception {
        long ts = System.currentTimeMillis();
        String userA = "userA_" + ts;
        String userB = "userB_" + ts;
        String password = "ValidPass123!";

        // Registracija oba korisnika
        registerUser(userA, password);
        registerUser(userB, password);

        // Prijava i dohvat tokena
        tokenUserA = loginAndGetToken(userA, password);
        tokenUserB = loginAndGetToken(userB, password);

        // UserA kreira zadatak
        taskIdOwnedByUserA = createTaskAndGetId(tokenUserA, "UserA zadatak");
    }

    @Test
    @DisplayName("Korisnik B ne smije dohvatiti zadatak korisnika A — mora dobiti 403")
    void userB_shouldNotReadUserA_task() throws Exception {
        mockMvc.perform(get("/tasks/" + taskIdOwnedByUserA)
                        .header("Authorization", "Bearer " + tokenUserB))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Korisnik B ne smije ažurirati zadatak korisnika A — mora dobiti 403")
    void userB_shouldNotUpdateUserA_task() throws Exception {
        mockMvc.perform(put("/tasks/" + taskIdOwnedByUserA)
                        .header("Authorization", "Bearer " + tokenUserB)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"Hacked title\",\"description\":\"opis od tocnog broja znakova\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Korisnik B ne smije obrisati zadatak korisnika A — mora dobiti 403")
    void userB_shouldNotDeleteUserA_task() throws Exception {
        mockMvc.perform(delete("/tasks/" + taskIdOwnedByUserA)
                        .header("Authorization", "Bearer " + tokenUserB))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Korisnik A smije pristupiti vlastitom zadatku — mora dobiti 200")
    void userA_shouldReadOwnTask() throws Exception {
        mockMvc.perform(get("/tasks/" + taskIdOwnedByUserA)
                        .header("Authorization", "Bearer " + tokenUserA))
                .andExpect(status().isOk());
    }

    // ── Pomoćne metode ────────────────────────────────────────────────

    private void registerUser(String username, String password) throws Exception {
        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(String.format(
                                "{\"username\":\"%s\",\"password\":\"%s\"}", username, password)))
                .andExpect(status().isOk());
    }

    private String loginAndGetToken(String username, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(String.format(
                                "{\"username\":\"%s\",\"password\":\"%s\"}", username, password)))
                .andExpect(status().isOk())
                .andReturn();

        // login vraća raw String token (vidljivo iz AuthController)
        return result.getResponse().getContentAsString();
    }

    private String createTaskAndGetId(String token, String title) throws Exception {
        MvcResult result = mockMvc.perform(post("/tasks")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(String.format(
                                "{\"title\":\"%s\",\"description\":\"opis od tocnog broja znakova\"}", title)))
                .andExpect(status().isOk())
                .andReturn();

        // Parsiranje ID-a iz JSON odgovora
        return objectMapper.readTree(
                        result.getResponse().getContentAsString())
                .get("id")
                .asText();
    }

    // =========================================================================
    // OWASP A01:2025 — Broken Access Control: Mass Data Leakage / Bypassing Scope
    // =========================================================================
    @Test
    @DisplayName("Korisnik B ne smije vidjeti zadatke korisnika A u listi svih zadataka")
    void userB_shouldNotSeeUserA_tasksInList() throws Exception {
        // Korisnik B traži listu svih zadataka preko GET /tasks
        // Budući da Korisnik B nema kreiranih zadataka (kreirao ih je samo UserA u setUp-u),
        // odgovor mora biti prazna lista "[]", čime dokazujemo da ne može zaobići opseg (scope).
        mockMvc.perform(get("/tasks")
                        .header("Authorization", "Bearer " + tokenUserB))
                .andExpect(status().isOk())
                .andExpect(result -> {
                    String content = result.getResponse().getContentAsString();
                    org.junit.jupiter.api.Assertions.assertEquals("[]", content.trim(),
                            "Korisnik B je uspio dohvatiti zadatke koji mu ne pripadaju kroz masovni ispis!");
                });
    }

    // =========================================================================
    // OWASP A01:2025 — Broken Access Control: Missing Token Revocation (Session Hijacking Risk)
    // =========================================================================
    @Test
    @DisplayName("Nakon poziva logout rute, važeći JWT token mora biti poništen i odbijen s 401")
    void tokenShouldBeInvalidated_afterLogout() throws Exception {
        // 1. Prvo provjeravamo da token ispravno radi prije logouta (mora vratiti 200)
        mockMvc.perform(get("/tasks")
                        .header("Authorization", "Bearer " + tokenUserA))
                .andExpect(status().isOk());

        // 2. Korisnik A poziva logout endpoint kako bi opozvao svoju sesiju/token
        mockMvc.perform(post("/auth/logout")
                        .header("Authorization", "Bearer " + tokenUserA))
                .andExpect(status().isNoContent());

        // 3. Korisnik A pokušava ponovo koristiti ISTI token.
        // Kontrola pristupa mora prepoznati da je token opozvan (npr. stavljen na crnu listu) i vratiti 401.
        mockMvc.perform(get("/tasks")
                        .header("Authorization", "Bearer " + tokenUserA))
                .andExpect(status().isUnauthorized());
    }
}