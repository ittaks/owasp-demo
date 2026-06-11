package com.demo.owasp.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integracijski testovi za OWASP A01:2025 — Broken Access Control
 * Verificira da SecurityConfig ispravno provodi "deny by default" princip.
 * Neautentificirani zahtjevi na zaštićene endpointe moraju biti odbijeni s 401.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AccessControlTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("GET /tasks bez tokena mora vratiti 401")
    void getTasksWithoutToken_shouldReturn401() throws Exception {
        mockMvc.perform(get("/tasks"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("POST /tasks bez tokena mora vratiti 401")
    void createTaskWithoutToken_shouldReturn401() throws Exception {
        mockMvc.perform(post("/tasks")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"Test task\",\"description\":\"opis od tocnog broja znakova\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("PUT /tasks/{id} bez tokena mora vratiti 401")
    void updateTaskWithoutToken_shouldReturn401() throws Exception {
        mockMvc.perform(put("/tasks/some-task-id")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"Updated\",\"description\":\"opis od tocnog broja znakova\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("DELETE /tasks/{id} bez tokena mora vratiti 401")
    void deleteTaskWithoutToken_shouldReturn401() throws Exception {
        mockMvc.perform(delete("/tasks/some-task-id"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("POST /auth/register i /auth/login moraju biti javno dostupni (ne smiju vratiti 401)")
    void authEndpoints_shouldBePubliclyAccessible() throws Exception {
        // Register mora biti dostupan — provjeravamo da nije zaštićen
        int registerStatus = mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"publicTestUser2\",\"password\":\"PublicPass123!\"}"))
                .andReturn().getResponse().getStatus();

        assertNotEquals(401, registerStatus, "Register ruta ne smije biti zaštićena s 401");

        // Login s upravo registriranim korisnikom — mora vratiti 200 s tokenom
        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"publicTestUser2\",\"password\":\"PublicPass123!\"}"))
                .andExpect(status().isOk());
    }
}