package com.demo.owasp.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

@Entity
@Data
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue
    private String id;

    private String username;

    private String password; // plain text (insecure)

    private String role; // USER or ADMIN
}
