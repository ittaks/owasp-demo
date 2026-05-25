package com.demo.owasp.dto.request;

import lombok.Data;

@Data
public class TaskFromXmlRequest {

    private String title;
    private String description;
}