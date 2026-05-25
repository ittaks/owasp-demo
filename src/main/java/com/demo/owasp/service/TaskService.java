package com.demo.owasp.service;

import com.demo.owasp.dto.TaskFromXmlRequest;
import com.demo.owasp.dto.request.TaskRequest;
import com.demo.owasp.dto.response.TaskResponse;
import com.demo.owasp.entity.Task;
import com.demo.owasp.entity.User;
import com.demo.owasp.repository.TaskRepository;
import com.demo.owasp.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
@Service
@RequiredArgsConstructor
public class TaskService {

    private final TaskRepository taskRepository;
    private final UserRepository userRepository;
    private final XmlParserService xmlParserService;


    private TaskResponse mapToResponse(Task task) {
        TaskResponse response = new TaskResponse();
        response.setId(task.getId());
        response.setTitle(task.getTitle());
        response.setDescription(task.getDescription());
        response.setOwnerUsername(task.getOwner().getUsername());
        return response;
    }

    public TaskResponse createTaskForUser(TaskRequest taskRequest, String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        Task task = new Task();
        task.setTitle(taskRequest.getTitle());
        task.setDescription(taskRequest.getDescription());
        task.setOwner(user);
        return mapToResponse(taskRepository.save(task));
    }
    // SIGURAN DOHVAT: Ako je korisnik ADMIN, vidi sve, inače se baza filtrira isključivo po ID-u vlasnika
    public List<TaskResponse> getTasksForUser(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        List<Task> tasks = "ADMIN".equalsIgnoreCase(user.getRole())
                ? taskRepository.findAll()
                : taskRepository.findByOwnerId(user.getId());

        return tasks.stream().map(this::mapToResponse).toList();
    }

    // STROGA KRITIČNA ZAŠTITA OD IDOR-a: Eksplicitna verifikacija vlasništva nad resursom
    public Task updateTaskForUser(Long taskId, TaskRequest request, String username) {
        Task task = taskRepository.findById(taskId)
                .orElseThrow(() -> new RuntimeException("Task not found"));

        // Provjera podudara li se autentificirani korisnik s vlasnikom zapisa u bazi podataka
        if (!task.getOwner().getUsername().equals(username)) {
            throw new AccessDeniedException("Access Denied: You do not have permissions to modify this task.");
        }

        task.setTitle(request.getTitle());
        task.setDescription(request.getDescription());

        return taskRepository.save(task);
    }
    // SIGURNA LOGIKA BRISANJA: Objedinjena provjera uloga i vlasništva zapisa
    public void deleteTaskForUser(Long taskId, String username) {
        Task task = taskRepository.findById(taskId)
                .orElseThrow(() -> new RuntimeException("Task not found"));

        // Dopusti brisanje isključivo ako je korisnik stvarni vlasnik zapisa ILI ako ima ulogu ADMIN
        boolean isAdmin = userRepository.findByUsername(username)
                .map(u -> "ADMIN".equalsIgnoreCase(u.getRole())).orElse(false);

        if (!task.getOwner().getUsername().equals(username) && !isAdmin) {
            throw new AccessDeniedException("Unauthorized to drop this resource.");
        }
        taskRepository.delete(task);
    }

    /**
     * OWASP A01 Secure File Import Implementation
     * * Uses cryptographically verified context session identifiers instead of
     * request parameters to prevent horizontal privilege escalations.
     */
    public TaskResponse createTaskFromXmlForUser(MultipartFile file, String username) {
        // 1. Process the incoming stream safely using defensive configurations
        TaskFromXmlRequest dto = xmlParserService.parse(file);

        // 2. Fetch context owner strictly via verified identity token bindings
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User context validation failure."));

        // 3. Build and persist resource properties
        Task task = new Task();
        task.setTitle(dto.getTitle());
        task.setDescription(dto.getDescription());
        task.setOwner(user);

        // 4. Return safe DTO encapsulation out to client visibility layers
        return mapToResponse(taskRepository.save(task));
    }
}