package com.demo.owasp.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OWASP A01 - Broken Access Control DEFENSE
 *
 * JWT koristimo za:
 * - server-side verifikaciju identiteta
 * - sprječavanje manipulacije userId (IDOR)
 * - osiguranje da client NE kontrolira identitet
 *
 * Token je potpisan → napadač ga ne može mijenjati
 */
@Service
public class JwtService {
    /*
     * OWASP A07:2025 ZAŠTITA
     *
     * Definiramo očekivani identitet izdavatelja
     * i primatelja tokena.
     */
    private final Set<String> activeTokens = ConcurrentHashMap.newKeySet();
    private static final String ISSUER = "owasp-demo";
    private static final String AUDIENCE = "owasp-demo-client";
    private final SecretKey key;

    public JwtService(@Value("${jwt.secret}") String secret) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }
    /*
     * OWASP A07:2025 ZAŠTITA
     *
     * Dodajemo:
     * - issuer (tko je izdao token)
     * - audience (za koga je token namijenjen)
     * - jti (jedinstveni identifikator tokena)
     *
     * Time sprječavamo:
     * - token confusion napade
     * - replay napade
     * - korištenje tokena iz drugih sustava
     */
    public String generateToken(String username, String role) {
        String tokenId = UUID.randomUUID().toString();
        activeTokens.add(tokenId);

        return Jwts.builder()
                .issuer(ISSUER)                          // novo u 0.12.x
                .audience().add(AUDIENCE).and()          // novo u 0.12.x
                .id(tokenId)
                .subject(username)
                .claim("role", role)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 1000L * 60 * 15))
                .signWith(key)                           // 0.12.x automatski detektira algoritam iz ključa
                .compact();
    }

    public String extractUsername(String token) {
        return validateAndGetClaims(token).getSubject();
    }

    public String extractRole(String token) {
        return (String) validateAndGetClaims(token).get("role");
    }

    /*
     * OWASP A07:2025 ZAŠTITA
     *
     * Omogućava kasniju implementaciju
     * logout-a i blacklistanja tokena.
     */
    public String extractTokenId(String token) {
        return validateAndGetClaims(token).getId();
    }
    public boolean isActiveToken(String tokenId) {
        return activeTokens.contains(tokenId);
    }

    public void deactivateToken(String tokenId) {
        activeTokens.remove(tokenId);
    }
    public Date extractExpiration(String token) {

        return validateAndGetClaims(token)
                .getExpiration();
    }

    private Jws<Claims> parse(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token);
    }

    private Claims validateAndGetClaims(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        if (!ISSUER.equals(claims.getIssuer())) {
            throw new JwtException("Invalid issuer");
        }

        // 0.12.x vraća Set<String>
        if (claims.getAudience() == null || !claims.getAudience().contains(AUDIENCE)) {
            throw new JwtException("Invalid audience");
        }

        return claims;
    }
}
