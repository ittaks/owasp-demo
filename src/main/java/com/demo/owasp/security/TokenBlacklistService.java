package com.demo.owasp.security;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class TokenBlacklistService {

    /*
     * OWASP A07:2025 ZAŠTITA
     *
     * Evidencija opozvanih JWT tokena.
     *
     * Ključ:
     * jti (JWT ID)
     *
     * Vrijednost:
     * vrijeme isteka tokena
     */
    private final Map<String, Instant> blacklistedTokens = new ConcurrentHashMap<>();

    public void blacklist(String tokenId, Instant expiresAt) {
        blacklistedTokens.put(tokenId, expiresAt);
    }

    public boolean isBlacklisted(String tokenId) {
        Instant expiry = blacklistedTokens.get(tokenId);

        if (expiry == null) {
            return false;
        }

        /*
         * OWASP A07:2025 ZAŠTITA
         *
         * Automatsko čišćenje isteklih tokena.
         */
        if (Instant.now().isAfter(expiry)) {
            blacklistedTokens.remove(tokenId);
            return false;
        }

        return true;
    }
}
