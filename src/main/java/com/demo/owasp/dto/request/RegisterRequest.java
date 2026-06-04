package com.demo.owasp.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RegisterRequest {

    @NotBlank(message = "Korisničko ime je obvezno.")
    @Size(min = 4, max = 30, message = "Korisničko ime mora imati između 4 i 30 znakova.")
    @Pattern(
            regexp = "^[a-zA-Z0-9_]*$",
            message = "Korisničko ime smije sadržavati samo slova, brojke i podvlaku."
    )
    private String username;

    /*
     * OWASP A07:2025 ZAŠTITA (CWE-521 Weak Password Requirements)
     *
     * Minimalna duljina povećana je na 12 znakova.
     * Moderna OWASP i NIST preporuka više se oslanja na duljinu
     * nego na prisiljavanje kompleksnih znakova.
     *
     * Time se značajno smanjuje uspješnost:
     * - brute-force napada
     * - password spraying napada
     * - credential stuffing varijacija
     */
    @NotBlank(message = "Lozinka je obvezna.")
    @Size(
            min = 12,
            max = 128,
            message = "Lozinka mora imati između 12 i 128 znakova."
    )
    private String password;
}