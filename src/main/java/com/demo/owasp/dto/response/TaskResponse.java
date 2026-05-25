package com.demo.owasp.dto.response;


import lombok.Data;

@Data
public class TaskResponse {
    private Long id;
    private String title;
    private String description;
    private String ownerUsername; // Safe exposure: hides internal IDs & raw passwords
}
