package com.demo.owasp.controller;

import com.demo.owasp.dto.request.TaskRequest;
import com.demo.owasp.dto.response.TaskResponse;
import com.demo.owasp.entity.Task;
import com.demo.owasp.service.TaskService;
import jakarta.validation.Valid; // [DODANO]
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.security.Principal;
import java.util.List;
/**
 * Kontroler za upravljanje HTTP zahtjevima povezanim sa zadacima.
 * Korištenjem anotacije @Valid osigurava se presretanje i odbijanje neispravnih unosa.
 */
@RestController
@RequestMapping("/tasks")
public class TaskController {

    private final TaskService taskService;

    public TaskController(TaskService taskService) {
        this.taskService = taskService;
    }

    // [IZMIJENJENO]: Dodana anotacija @Valid ispred @RequestBody
    @PostMapping
    public ResponseEntity<TaskResponse> createTask(@Valid @RequestBody TaskRequest taskRequest, Principal principal) {
        return ResponseEntity.ok(taskService.createTaskForUser(taskRequest, principal.getName()));
    }

    @GetMapping
    public List<TaskResponse> getAll(Principal principal) {
        return taskService.getTasksForUser(principal.getName());
    }

    // [IZMIJENJENO]: Dodana anotacija @Valid ispred @RequestBody
    @PutMapping("/{id}")
    public ResponseEntity<Task> update(@PathVariable String id, @Valid @RequestBody TaskRequest taskRequest, Principal principal) {
        return ResponseEntity.ok(taskService.updateTaskForUser(id, taskRequest, principal.getName()));
    }
    @GetMapping("/{id}")
    public ResponseEntity<TaskResponse> getById(@PathVariable String id, Principal principal) {
        return ResponseEntity.ok(taskService.getTaskByIdForUser(id, principal.getName()));
    }
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable String id, Principal principal) {
        taskService.deleteTaskForUser(id, principal.getName());
        return ResponseEntity.noContent().build();
    }
    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<TaskResponse> createTaskFromXml(
            @RequestParam("file") MultipartFile file,
            java.security.Principal principal) {

        // Dohvaćamo username trenutno prijavljenog korisnika iz sigurnosnog konteksta
        String username = principal.getName();

        // Pozivamo tvoj zaštićeni servis
        TaskResponse response = taskService.createTaskFromXmlForUser(file, username);

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}