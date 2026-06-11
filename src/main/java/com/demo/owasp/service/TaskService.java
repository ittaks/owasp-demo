package com.demo.owasp.service;

import com.demo.owasp.dto.TaskFromXmlRequest;
import com.demo.owasp.dto.request.TaskRequest;
import com.demo.owasp.dto.response.TaskResponse;
import com.demo.owasp.entity.Task;
import com.demo.owasp.entity.User;
import com.demo.owasp.exception.ResourceNotFoundException;
import com.demo.owasp.repository.TaskRepository;
import com.demo.owasp.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
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

    // [OWASP A06 ZAŠTITA]: Maksimalan broj dopuštenih zadataka po korisniku (Business Logic Limit).
    // Štiti od scenarija masovnog kreiranja zapisa (Denial of Wallet / Resource Exhaustion - scenario br. 2 iz dokumentacije).
    private static final int MAX_TASLES_PER_USER = 100;

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

        // [OWASP A06 ZAŠTITA - CWE-799 / CWE-841]: Provjera stanja i poslovnih limita prije perzistencije.
        // Sprječavamo napadača da kroz automatizirane skripte preplavi bazu podataka i naruši stabilnost sustava.
        long existingCount = taskRepository.findByOwnerId(user.getId()).size();
        if (existingCount >= MAX_TASLES_PER_USER) {
            throw new IllegalStateException("Limit kreiranja zadataka je dosegnut. Sustav štiti resurse od zloupotrebe.");
        }

        Task task = new Task();
        task.setTitle(taskRequest.getTitle());
        task.setDescription(taskRequest.getDescription());
        task.setOwner(user);
        return mapToResponse(taskRepository.save(task));
    }

    public List<TaskResponse> getTasksForUser(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        List<Task> tasks = "ADMIN".equalsIgnoreCase(user.getRole()) ? taskRepository.findAll() : taskRepository.findByOwnerId(user.getId());
        return tasks.stream().map(this::mapToResponse).toList();
    }

    public Task updateTaskForUser(String taskId, TaskRequest request, String username) {
        Task task = taskRepository.findById(taskId)
                .orElseThrow(() -> new ResourceNotFoundException("Task not found"));

        if (!task.getOwner().getUsername().equals(username)) {
            throw new AccessDeniedException("Access Denied: You do not have permissions to modify this task.");
        }
        task.setTitle(request.getTitle());
        task.setDescription(request.getDescription());
        return taskRepository.save(task);
    }

    public void deleteTaskForUser(String taskId, String username) {
        Task task = taskRepository.findById(taskId)
                .orElseThrow(() -> new ResourceNotFoundException("Task not found"));

        boolean isAdmin = userRepository.findByUsername(username)
                .map(u -> "ADMIN".equalsIgnoreCase(u.getRole())).orElse(false);

        if (!task.getOwner().getUsername().equals(username) && !isAdmin) {
            throw new AccessDeniedException("Unauthorized to drop this resource.");
        }
        taskRepository.delete(task);
    }

    public TaskResponse createTaskFromXmlForUser(MultipartFile file, String username) {
        // [OWASP A06 ZAŠTITA - CWE-434: Unrestricted Upload of File with Dangerous Type]:
        // Provjera tipa i ekstenzije datoteke na razini aplikacijskog dizajna prije prosljeđivanja parseru.
        String contentType = file.getContentType();
        if (contentType == null || !contentType.equals("text/xml") && !contentType.equals("application/xml")) {
            throw new IllegalArgumentException("Nedopušten tip datoteke! Sustav prihvaća isključivo validne XML strukture.");
        }

        TaskFromXmlRequest dto = xmlParserService.parse(file);
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Neuspjela validacija korisničkog konteksta."));

        // Provjera limita i ovdje za workflow robusnost
        long existingCount = taskRepository.findByOwnerId(user.getId()).size();
        if (existingCount >= MAX_TASLES_PER_USER) {
            throw new IllegalStateException("Limit kreiranja zadataka je dosegnut.");
        }

        Task task = new Task();
        task.setTitle(dto.getTitle());
        task.setDescription(dto.getDescription());
        task.setOwner(user);

        return mapToResponse(taskRepository.save(task));
    }

    public TaskResponse getTaskByIdForUser(String id, String username) {
        Task task = taskRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Task not found"));

        boolean isAdmin = userRepository.findByUsername(username)
                .map(u -> "ADMIN".equalsIgnoreCase(u.getRole())).orElse(false);

        if (!task.getOwner().getUsername().equals(username) && !isAdmin) {
            throw new AccessDeniedException("Access Denied: You do not have permissions to view this task.");
        }

        return mapToResponse(task);
    }
}