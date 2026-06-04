package com.demo.owasp.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

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
    private final Key key;// OWASP A02: Čitanje eksternaliziranog ključa umjesto generiranja novog pri svakom startu
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
                .setIssuer("owasp-demo")
                .setAudience("owasp-demo-client")
                .setId(tokenId)
                .setSubject(username)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(
                        new Date(
                                System.currentTimeMillis()
                                        + 1000L * 60 * 15
                        )
                )
                .signWith(key, SignatureAlgorithm.HS512) //a8
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
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token);
    }

    private Claims validateAndGetClaims(String token) {

        Claims claims = Jwts.parserBuilder()
                        .setSigningKey(key)
                        .build()
                        .parseClaimsJws(token)
                        .getBody();

        /*
         * OWASP A07:2025 ZAŠTITA
         * Token mora dolaziti od očekivanog izdavatelja.
         */
        if (!ISSUER.equals(claims.getIssuer())) {
            throw new JwtException("Invalid issuer");
        }
        /*
         * OWASP A07:2025 ZAŠTITA
         * Token mora biti namijenjen ovoj aplikaciji.
         */
        if (!AUDIENCE.equals(claims.getAudience())) {
            throw new JwtException("Invalid audience");
        }

        return claims;
    }
}
