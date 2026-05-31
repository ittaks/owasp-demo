package com.demo.owasp.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import jakarta.validation.constraints.Pattern;
import lombok.Data;
/**
 * DTO objekt za prihvaćanje zahtjeva za kreiranje ili izmjenu zadatka.
 * Sadrži restriktivna pravila validacije kako bi se spriječio unos malicioznog koda.
 */
@Data
public class TaskRequest {

    @NotBlank(message = "Naslov ne smije biti prazan.")
    @Size(min = 3, max = 100, message = "Naslov mora imati između 3 i 100 znakova.")
    // Sprječavamo unos HTML tagova i specijalnih skriptnih znakova (XSS i HTML Injection obrana)
    @Pattern(regexp = "^[a-zA-Z0-9 IdŠšĐđČčĆćŽž.,!?-]*$", message = "Naslov sadrži nedopuštene znakove.")
    private String title;

    @NotBlank(message = "Opis ne smije biti prazan.")
    @Size(min = 10, max = 2000, message = "Opis može imati najviše 2000 znakova.")
    private String description;
}