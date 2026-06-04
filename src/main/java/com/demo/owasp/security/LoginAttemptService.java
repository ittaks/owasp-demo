package com.demo.owasp.security;

import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class LoginAttemptService {

    /*
     * OWASP A07:2025 ZAŠTITA (CWE-307)
     *
     * Broji neuspjele prijave po korisničkom računu.
     * Cilj je ograničiti brute-force i credential stuffing napade.
     */
    private final Map<String, Integer> failedAttempts =
            new ConcurrentHashMap<>();

    /*
     * OWASP A07:2025 ZAŠTITA
     *
     * Evidencija zaključanih računa.
     * Vrijednost predstavlja trenutak isteka zaključavanja.
     */
    private final Map<String, Instant> lockedAccounts =
            new ConcurrentHashMap<>();

    private static final int MAX_ATTEMPTS = 5;

    private static final Duration LOCK_DURATION =
            Duration.ofMinutes(15);

    public boolean isLocked(String username) {
        Instant lockUntil = lockedAccounts.get(username);

        if (lockUntil == null) {
            return false;
        }

        if (Instant.now().isAfter(lockUntil)) {
            lockedAccounts.remove(username);
            failedAttempts.remove(username);
            return false;
        }

        return true;
    }

    public void loginSucceeded(String username) {
        failedAttempts.remove(username);
        lockedAccounts.remove(username);
    }

    public void loginFailed(String username) {
        int count = failedAttempts.merge(username, 1, Integer::sum);
        /*
         * OWASP A07:2025 ZAŠTITA
         *
         * Nakon više uzastopnih neuspješnih pokušaja
         * račun se privremeno zaključava.
         */
        if (count >= MAX_ATTEMPTS) {
            lockedAccounts.put(username, Instant.now().plus(LOCK_DURATION));
        }
    }
}