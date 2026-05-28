package com.demo.owasp.controller;

import com.demo.owasp.dto.request.TaskRequest;
import com.demo.owasp.dto.response.TaskResponse;
import com.demo.owasp.entity.Task;
import com.demo.owasp.service.TaskService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.security.Principal;
import java.util.List;
@RestController
@RequestMapping("/tasks")
public class TaskController {

    private final TaskService taskService;

    public TaskController(TaskService taskService) {
        this.taskService = taskService;
    }

    // SANACIJA PROPUSA: Korisnički identitet se izvlači iz sesije poslužitelja (Principal)
    @PostMapping
    public ResponseEntity<TaskResponse> createTask(@RequestBody TaskRequest taskRequest, Principal principal) {
        String currentUsername = principal.getName();
        return ResponseEntity.ok(taskService.createTaskForUser(taskRequest, principal.getName()));
    }

    // HORIZONTALNA IZOLACIJA: Korisnici mogu dohvatiti isključivo svoje zadatke
    @GetMapping
    public List<TaskResponse> getAll(Principal principal) {
        return taskService.getTasksForUser(principal.getName());
    }

    // ZAŠTITA OD ZAOBILAŽENJA ZAPISA: Servis provjerava vlasništvo prije izmjene resursa
    @PutMapping("/{id}")
    public ResponseEntity<Task> update(@PathVariable String id, @RequestBody TaskRequest taskRequest,
                                       Principal principal) {
        return ResponseEntity.ok(taskService.updateTaskForUser(id, taskRequest, principal.getName()));
    }

    // OBJEDINJENO SIGURNO BRISANJE: Spriječeno dvostruko mapiranje rute.
    // Servis rješava logiku: dopušteno je ako si vlasnik zapisa ILI ako si ADMIN.
    @DeleteMapping("/{id}")
    public ResponseEntity<String> delete(@PathVariable String id, Principal principal) {
        taskService.deleteTaskForUser(id, principal.getName());
        return ResponseEntity.ok("Task successfully removed.");
    }

    // SIGURAN IMPORT PUTEM XML-a: Spojeno s provjerenim kontekstom autentificiranog korisnika
    @PostMapping(value = "/import", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<TaskResponse> importTask(
            @RequestParam("file") MultipartFile file,
            Principal principal) {

        TaskResponse response = taskService.createTaskFromXmlForUser(file, principal.getName());
        return ResponseEntity.ok(response);
    }
}