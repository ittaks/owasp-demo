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
    @Pattern(regexp = "^[a-zA-Z0-9 IdŠšĐđČčĆćŽž.,!?-]*$", message = "Naslov sadrži nedopuštene znakove.")
    private String title;

    @NotBlank(message = "Opis ne smije biti prazan.")
    @Size(min = 10, max = 2000, message = "Opis može imati najviše 2000 znakova.")
    // UKLANJANJE PROPUSTA (XSS): Primjena restriktivnog regularnog izraza koji dopušta tekst, brojeve i osnovnu interpunkciju,
    // ali eksplicitno zabranjuje znakove <, >, & i ostale elemente koji se koriste za HTML/Script injekciju.
    @Pattern(
            regexp = "^[a-zA-Z0-9 IdŠšĐđČčĆćŽž.,!?()\"'#:\n\r-]*$",
            message = "Opis sadrži nedopuštene znakove (HTML i skriptne oznake nisu dopuštene)."
    )
    private String description;
}