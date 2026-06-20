package com.demo.owasp.security;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OWASP A06:2025 ZAŠTITA - Kontrola učestalosti zahtjeva (Rate Limiting)
 *
 * Koristi Bucket4j implementaciju algoritma "token bucket" kako bi se osigurao
 * pravi vremenski prozor obnavljanja, za razliku od trajnog (lifetime) brojača.
 * Autentifikacijski endpointi (/auth/**) imaju strože ograničenje jer su
 * primarna meta automatiziranih napada pogađanjem vjerodajnica (Credential Stuffing).
 */
@Component
public class RateLimitingInterceptor implements HandlerInterceptor {

    private final Map<String, Bucket> apiBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> authBuckets = new ConcurrentHashMap<>();

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String ip = request.getRemoteAddr();
        boolean isAuthEndpoint = request.getRequestURI().startsWith("/auth/");

        Bucket bucket = isAuthEndpoint
                ? authBuckets.computeIfAbsent(ip, k -> newAuthBucket())
                : apiBuckets.computeIfAbsent(ip, k -> newApiBucket());

        if (bucket.tryConsume(1)) {
            return true;
        }

        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType("application/json");
        response.getWriter().write(
                "{\"error\":\"Too Many Requests\",\"message\":\"Limit broja zahtjeva je dosegnut. Pokušajte ponovno kasnije.\"}"
        );
        return false;
    }

    private Bucket newAuthBucket() {
        Bandwidth limit = Bandwidth.classic(5, Refill.intervally(5, Duration.ofMinutes(1)));
        return Bucket.builder().addLimit(limit).build();
    }

    private Bucket newApiBucket() {
        Bandwidth limit = Bandwidth.classic(100, Refill.intervally(100, Duration.ofMinutes(1)));
        return Bucket.builder().addLimit(limit).build();
    }
}