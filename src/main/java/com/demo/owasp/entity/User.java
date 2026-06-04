package com.demo.owasp.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.Data;

@Entity
@Data
public class User {

    @Id
    @GeneratedValue
    private String id;

    /*
     * OWASP A07:2025 ZAŠTITA
     *
     * Jedinstveno korisničko ime na razini baze podataka.
     * Čak i ako aplikacijska validacija zakaže,
     * baza neće dopustiti duplikate.
     */
    @Column(unique = true, nullable = false)
    private String username;

    private String password; // plain text (insecure)

    private String role; // USER or ADMIN
}
