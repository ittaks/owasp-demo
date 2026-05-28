package com.demo.owasp.repository;

import com.demo.owasp.entity.Task;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface TaskRepository extends JpaRepository<Task, String> {
    List<Task> findByOwnerId(String ownerId);
}
