package com.demo.owasp.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;

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

    private final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    public String generateToken(String username, String role) {
        return Jwts.builder()
                .setSubject(username)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 15)) // short-lived
                .signWith(key)
                .compact();
    }

    public String extractUsername(String token) {
        return parse(token).getBody().getSubject();
    }

    public String extractRole(String token) {
        return (String) parse(token).getBody().get("role");
    }

    private Jws<Claims> parse(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token);
    }
}
