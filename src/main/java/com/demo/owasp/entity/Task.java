package com.demo.owasp.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import lombok.Data;
import lombok.Getter;

@Entity
@Data
@Getter
public class Task {

    @Id
    @GeneratedValue
    private String id;

    private String title;

    private String description;

    @ManyToOne
    private User owner;
}
