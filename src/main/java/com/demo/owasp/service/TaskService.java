package com.demo.owasp.service;

import com.demo.owasp.dto.request.TaskFromXmlRequest;
import com.demo.owasp.dto.request.TaskRequest;
import com.demo.owasp.entity.Task;
import com.demo.owasp.entity.User;
import com.demo.owasp.repository.TaskRepository;
import com.demo.owasp.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Service
@RequiredArgsConstructor
public class TaskService {

    private final TaskRepository taskRepository;
    private final UserRepository userRepository;
    private final XmlParserService xmlParserService;

    public Task createTask(String userId, TaskRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Task task = new Task();
        task.setTitle(request.getTitle());
        task.setDescription(request.getDescription());
        task.setOwner(user);

        return taskRepository.save(task);
    }

    public List<Task> getAllTasks() {
        return taskRepository.findAll(); // no filtering
    }

    public Task updateTask(String taskId, TaskRequest request) {
        Task task = taskRepository.findById(taskId)
                .orElseThrow(() -> new RuntimeException("Task not found"));

        task.setTitle(request.getTitle());
        task.setDescription(request.getDescription());

        return taskRepository.save(task);
    }

    public void deleteTask(String taskId) {
        taskRepository.deleteById(taskId);
    }

    public Task createFromXml(String username, MultipartFile file) {

        TaskFromXmlRequest dto = xmlParserService.parse(file);

        User user = userRepository.findByUsername(username);

        Task task = new Task();
        task.setTitle(dto.getTitle());
        task.setDescription(dto.getDescription());
        task.setOwner(user);

        return taskRepository.save(task);
    }

    public Task updateFromXml(String id, String username, MultipartFile file) {

        TaskFromXmlRequest dto = xmlParserService.parse(file);

        Task task = taskRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Task not found"));

        // OWASP A01 - ownership enforcement
        if (!task.getOwner().getUsername().equals(username)) {
            throw new RuntimeException("Access denied");
        }

        task.setTitle(dto.getTitle());
        task.setDescription(dto.getDescription());

        return taskRepository.save(task);
    }
}
