package com.demo.owasp.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Slf4j
public class LoginAttemptService {

    private final Map<String, Integer> failedAttempts =
            new ConcurrentHashMap<>();

    private final Map<String, Instant> lockouts =
            new ConcurrentHashMap<>();

    private static final int MAX_ATTEMPTS = 5;
    private static final Duration LOCK_TIME = Duration.ofMinutes(15);

    /*
     * OWASP A07:2025 ZAŠTITA
     * Zaključavanje korisničkog računa nakon višestrukih
     * neuspjelih pokušaja prijave.
     * Smanjuje uspješnost brute-force i credential stuffing napada.
     */
    public void loginFailed(String username) {

        int count = failedAttempts.merge(username, 1, Integer::sum);

        if (count >= MAX_ATTEMPTS) {
            lockouts.put(username, Instant.now().plus(LOCK_TIME));
            /*
             * OWASP A07:2025 ZAŠTITA
             *
             * Evidentiranje sumnjivog ponašanja.
             * Pomaže otkrivanju brute-force kampanja.
             */
            log.warn("SECURITY EVENT: Account locked due to excessive login failures. Username={}", username);
        }
    }

    public void loginSucceeded(String username) {
        failedAttempts.remove(username);
        lockouts.remove(username);
    }

    public boolean isLocked(String username) {

        Instant lockedUntil = lockouts.get(username);

        return lockedUntil != null &&
                lockedUntil.isAfter(Instant.now());
    }
}