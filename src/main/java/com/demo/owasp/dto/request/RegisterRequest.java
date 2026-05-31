package com.demo.owasp.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import jakarta.validation.constraints.Pattern;
import lombok.Data;
/**
 * DTO objekt za registraciju novog korisničkog računa.
 * Osigurava da korisničko ime zadovoljava strogu allow-list strukturu znakova.
 */
@Data
public class RegisterRequest {

    @NotBlank(message = "Korisničko ime je obvezno.")
    @Size(min = 4, max = 30, message = "Korisničko ime mora imati između 4 i 30 znakova.")
    @Pattern(regexp = "^[a-zA-Z0-9_]*$", message = "Korisničko ime smije sadržavati samo slova, brojke i podvlaku.")
    private String username;

    @NotBlank(message = "Lozinka je obvezna.")
    @Size(min = 8, max = 64, message = "Lozinka mora imati između 8 i 64 znakova.")
    private String password;
}