package com.demo.owasp.security;

public class LogSanitizer {

    /**
     * OWASP A09 ZAŠTITA - Obrana od Log Injection napada (CWE-117)
     * Neutralizira znakove za novi redak (\r, \n) kako napadač
     * ne bi mogao prelomiti poruku i lažirati strukturu log datoteke.
     */
    public static String sanitize(String input) {
        if (input == null) {
            return null;
        }
        // Zamjenjuje Carriage Return (\r) i Line Feed (\n) sa sigurnim separatorom
        // čime se osigurava da cijeli zapis ostane unutar JEDNOG retka u logu.
        return input.replace("\n", " [NEWLINE] ")
                .replace("\r", " [CR] ");
    }
}