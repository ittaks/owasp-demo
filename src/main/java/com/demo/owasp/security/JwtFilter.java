package com.demo.owasp.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

@Slf4j
public class JwtFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final TokenBlacklistService tokenBlacklistService;

    public JwtFilter(
            JwtService jwtService,
            TokenBlacklistService tokenBlacklistService
    ) {
        this.jwtService = jwtService;
        this.tokenBlacklistService = tokenBlacklistService;
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain)
            throws IOException, ServletException {

        String header = request.getHeader("Authorization");

        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);

            try {
                /*
                 * OWASP A07:2025 ZAŠTITA - Premješteno unutar try-catch bloka!
                 * Ako ekstrakcija tokenId ili bilo koje tvrdnje ne uspije zbog manipulacije,
                 * iznimka će biti sigurno uhvaćena bez rušenja aplikacije.
                 */
                String tokenId = jwtService.extractTokenId(token);

                if (tokenBlacklistService.isBlacklisted(tokenId) || !jwtService.isActiveToken(tokenId)) {
                    chain.doFilter(request, response);
                    return;
                }

                String username = jwtService.extractUsername(token);
                String role = jwtService.extractRole(token);

                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    List<SimpleGrantedAuthority> authorities = Collections.singletonList(
                            new SimpleGrantedAuthority("ROLE_" + role)
                    );

                    UsernamePasswordAuthenticationToken auth =
                            new UsernamePasswordAuthenticationToken(
                                    username,
                                    null,
                                    authorities
                            );

                    SecurityContextHolder.getContext().setAuthentication(auth);
                }

            } catch (Exception e) {
                // [OWASP A09 ZAŠTITA] - Logiranje pokušaja manipulacije autorizacijskim mehanizmima
                // Ne logiramo cijeli stacktrace (e) s log.error da ne zagušujemo disk, već radimo čist warn
                log.warn("SECURITY WARNING: Detektiran je nevažeći, istekao ili modificirani JWT token. Pristup odbijen. Detalji: {}", e.getMessage());

                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter().write("{\"error\": \"Unauthorized\", \"message\": \"Token nije valjan ili je modificiran.\"}");
                return;
            }
        }

        chain.doFilter(request, response);
    }
}