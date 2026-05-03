package com.demo.owasp.controller;

import com.demo.owasp.dto.request.TaskRequest;
import com.demo.owasp.entity.Task;
import com.demo.owasp.service.TaskService;
import com.demo.owasp.service.XmlParserService;
import lombok.RequiredArgsConstructor;
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

import java.util.List;

@RestController
@RequestMapping("/tasks")
@RequiredArgsConstructor
public class TaskController {

    private final TaskService taskService;

    @PostMapping
    public Task createTask(@RequestParam String userId,
                           @RequestBody TaskRequest request) {
        return taskService.createTask(userId, request);
    }

    @GetMapping
    public List<Task> getAll() {
        return taskService.getAllTasks();
    }

    @PutMapping("/{id}")
    public Task update(@PathVariable String id,
                       @RequestBody TaskRequest request) {
        return taskService.updateTask(id, request);
    }

    @DeleteMapping("/{id}")
    public void delete(@PathVariable String id) {
        taskService.deleteTask(id);
    }

    @PostMapping("/import")
    public Task importTask(@RequestParam String userId,
                           @RequestParam("file") MultipartFile file) {

        return taskService.createFromXml(userId, file);
    }

    @PutMapping("/{id}/import")
    public Task updateFromXml(@PathVariable String id,
                              @RequestParam String userId,
                              @RequestParam("file") MultipartFile file) {

        return taskService.updateFromXml(id, userId, file);
    }
}