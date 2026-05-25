package com.demo.owasp.mapper;

import com.demo.owasp.dto.response.TaskResponse;
import com.demo.owasp.entity.Task;


public class TaskMapper {

    private TaskResponse mapToResponse(Task task) {
        TaskResponse response = new TaskResponse();
        response.setId(task.getId());
        response.setTitle(task.getTitle());
        response.setDescription(task.getDescription());
        response.setOwnerUsername(task.getOwner().getUsername());
        return response;
    }
}
