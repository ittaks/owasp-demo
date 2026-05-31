package com.demo.owasp.controller;

import com.demo.owasp.dto.request.TaskRequest;
import com.demo.owasp.dto.response.TaskResponse;
import com.demo.owasp.entity.Task;
import com.demo.owasp.service.TaskService;
import jakarta.validation.Valid; // [DODANO]
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
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

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable String id, Principal principal) {
        taskService.deleteTaskForUser(id, principal.getName());
        return ResponseEntity.noContent().build();
    }
}