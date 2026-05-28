package com.demo.owasp.entity;

import com.demo.owasp.security.EncryptedStringConverter;
import jakarta.persistence.*;
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

    // OWASP A04 PROTECTION: Podaci u mirovanju (at rest) se automatski šifriraju primjenom konvertera.
    // U H2 bazi podataka podaci će biti spremljeni kao nečitljivi Base64 AES-GCM string,
    // dok unutar Java koda radite s čistim tekstom potpuno transparentno.
    @Convert(converter = EncryptedStringConverter.class)
    @Column(columnDefinition = "TEXT") // Osiguravamo prostor za rast duljine zbog Base64 i IV-a
    private String description;

    @ManyToOne
    private User owner;
}