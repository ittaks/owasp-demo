package com.demo.owasp.security;

import org.springframework.stereotype.Component;

import java.util.Set;

@Component
public class CommonPasswordValidator {

    /*
     * OWASP A07:2025 ZAŠTITA (CWE-1391 / CWE-1393)
     *
     * Blokiramo najčešće korištene i kompromitirane lozinke.
     * Za lokalnu aplikaciju nije potrebno koristiti vanjske servise
     * poput HaveIBeenPwned, ali je preporučljivo odbiti očito
     * nesigurne lozinke.
     */
    private static final Set<String> COMMON_PASSWORDS = Set.of(
            "password",
            "password123",
            "admin",
            "admin123",
            "qwerty",
            "qwerty123",
            "12345678",
            "123456789",
            "welcome123",
            "letmein",
            "test1234"
    );

    public boolean isWeak(String password) {

        if (password == null) {
            return true;
        }

        return COMMON_PASSWORDS.contains(
                password.trim().toLowerCase()
        );
    }
}