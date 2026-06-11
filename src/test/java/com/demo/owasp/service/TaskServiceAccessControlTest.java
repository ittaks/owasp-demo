package com.demo.owasp.service;

import com.demo.owasp.entity.Task;
import com.demo.owasp.entity.User;
import com.demo.owasp.repository.TaskRepository;
import com.demo.owasp.repository.UserRepository; // [DODANO] Uvoz repozitorija
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

/**
 * Jedinični (Unit) testovi za provjeru OWASP A01:2025 — Broken Access Control na nivou servisa.
 */
@ExtendWith(MockitoExtension.class)
class TaskServiceAccessControlTest {

    @Mock
    private TaskRepository taskRepository;

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private TaskService taskService;

    // =========================================================================
    // OWASP A01:2025 — Broken Access Control: Business Logic IDOR Bypass
    // =========================================================================
    @Test
    @DisplayName("Servis mora baciti AccessDeniedException kada korisnik pokuša pristupiti tuđem zadatku")
    void taskService_shouldThrowException_whenUserIsNotOwner() {
        // Aranžiranje (Setup)
        String taskId = "task-123";
        String ownerUsername = "korisnikA";
        String attackerUsername = "korisnikB"; // Napadač

        // 1. Kreiramo stvarnog vlasnika zadatka (UserA)
        User mockOwner = new User();
        mockOwner.setUsername(ownerUsername);

        // 2. Kreiramo napadača (UserB) koji pokušava izvršiti neovlašteni pristup
        User mockAttacker = new User();
        mockAttacker.setUsername(attackerUsername);

        // 3. Kreiramo zadatak i postavljamo mu vlasnika (UserA)
        Task mockTask = new Task();
        mockTask.setId(taskId);
        mockTask.setOwner(mockOwner);

        // 4. Definiramo ponašanje repozitorija (Stubbing)
        // Kada servis traži zadatak, vrati zadatak od Korisnika A
        when(taskRepository.findById(taskId)).thenReturn(Optional.of(mockTask));

        // Kada servis traži korisnika po username-u (linija 118 u tvom servisu), vrati Korisnika B
        when(userRepository.findByUsername(attackerUsername)).thenReturn(Optional.of(mockAttacker));

        // Čin i Provjera (Act & Assert)
        // Poziv servisa s ID-jem zadatka od Korisnika A i imenom Korisnika B mora baciti AccessDeniedException
        assertThrows(AccessDeniedException.class, () -> {
            taskService.getTaskByIdForUser(taskId, attackerUsername);
        }, "Servisni sloj je dopustio korisniku B da dohvati zadatak od korisnika A!");
    }
}