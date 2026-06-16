package com.demo.owasp.config;

import com.demo.owasp.entity.Task;
import com.demo.owasp.entity.User;
import com.demo.owasp.repository.TaskRepository;
import com.demo.owasp.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class DataSeeder {

    @Bean
    CommandLineRunner seedData(
            UserRepository userRepository,
            TaskRepository taskRepository,
            PasswordEncoder passwordEncoder) {

        return args -> {

            if (userRepository.count() > 0) {
                return;
            }

            // USERS

            User admin = new User();
            admin.setUsername("admin");
            admin.setPassword(passwordEncoder.encode("admin123"));
            admin.setRole("ADMIN");
            admin = userRepository.save(admin);

            User marko = new User();
            marko.setUsername("marko");
            marko.setPassword(passwordEncoder.encode("marko123"));
            marko.setRole("USER");
            marko = userRepository.save(marko);

            User ana = new User();
            ana.setUsername("ana");
            ana.setPassword(passwordEncoder.encode("ana123"));
            ana.setRole("USER");
            ana = userRepository.save(ana);

            User ivan = new User();
            ivan.setUsername("ivan");
            ivan.setPassword(passwordEncoder.encode("ivan123"));
            ivan.setRole("USER");
            ivan = userRepository.save(ivan);

            // TASKS

            createTask(
                    taskRepository,
                    "Security Audit",
                    "Review application security controls and OWASP findings",
                    admin);

            createTask(
                    taskRepository,
                    "Dependency Update",
                    "Update vulnerable Maven dependencies",
                    admin);

            createTask(
                    taskRepository,
                    "Implement Login",
                    "Create authentication endpoint and JWT support",
                    marko);

            createTask(
                    taskRepository,
                    "Write Unit Tests",
                    "Increase code coverage above eighty percent",
                    marko);

            createTask(
                    taskRepository,
                    "Prepare Documentation",
                    "Write API documentation for external consumers",
                    ana);

            createTask(
                    taskRepository,
                    "UI Improvements",
                    "Improve dashboard layout and responsiveness",
                    ana);

            createTask(
                    taskRepository,
                    "Docker Optimization",
                    "Reduce image size and improve build speed",
                    ivan);

            createTask(
                    taskRepository,
                    "CI Pipeline",
                    "Add Trivy scan and SBOM generation",
                    ivan);
        };
    }

    private void createTask(
            TaskRepository repository,
            String title,
            String description,
            User owner) {

        Task task = new Task();
        task.setTitle(title);
        task.setDescription(description);
        task.setOwner(owner);

        repository.save(task);
    }
}