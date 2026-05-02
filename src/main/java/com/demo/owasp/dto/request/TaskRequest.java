package com.demo.owasp.dto.request;

import lombok.Data;

@Data
public class TaskRequest {
    private String title;
    private String description;
}
