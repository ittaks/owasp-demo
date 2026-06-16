package com.demo.owasp.config;

import com.demo.owasp.security.JwtFilter;
import com.demo.owasp.security.JwtService;
import com.demo.owasp.security.TokenBlacklistService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
// [OWASP A06 ZAŠTITA]: Omogućavanje provjere autorizacije na razini metoda (npr. @PreAuthorize).
// Dizajniramo aplikaciju po principu "Najmanjih privilegija" (CWE-269) čime osiguravamo kontrolu na više razina.
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final JwtService jwtService;
    private final TokenBlacklistService tokenBlacklistService;
    private final String allowedOrigins;

    public SecurityConfig(JwtService jwtService, @Value("${app.cors.allowed-origins}") String allowedOrigins, TokenBlacklistService tokenBlacklistService) {
        this.jwtService = jwtService;
        this.tokenBlacklistService = tokenBlacklistService;
        this.allowedOrigins = allowedOrigins;
    }

    @Bean
    @Profile("dev")
    @Order(0)
    public SecurityFilterChain h2ConsoleSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
                .securityMatcher("/h2-console/**")
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .csrf(csrf -> csrf.disable())
                .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()))
                .build();
    }

    @Bean
    @Order(1)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.configurationSource(request -> {
                    var config = new org.springframework.web.cors.CorsConfiguration();
                    config.setAllowedOrigins(java.util.List.of(allowedOrigins));
                    config.setAllowedMethods(java.util.List.of("GET", "POST", "PUT", "DELETE"));
                    config.setAllowedHeaders(java.util.List.of("Authorization", "Content-Type"));
                    return config;
                }))
                .headers(headers -> headers
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(31536000)
                        )
                        .cacheControl(cache -> {})
                        .frameOptions(frame -> frame.deny())
                        .contentSecurityPolicy(csp -> csp
                                .policyDirectives(
                                        "default-src 'self'; " +
                                                "frame-ancestors 'none'; " +
                                                "object-src 'none'; " +
                                                "base-uri 'self'"
                                )
                        )
                )
                // [OWASP A01 ZAŠTITA]: Eksplicitna konfiguracija HTTP 401 za neautentificirane zahtjeve.
                // Spring Security defaultno vraća 403, što maskira razliku između neautentificiranog (401)
                // i neovlaštenog (403) pristupa. Ispravna semantika HTTP statusa bitna je za WAF i monitoring.
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((request, response, authException) ->
                                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized"))
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**").permitAll()

                        // HEALTH endpointi (safe exposure)
                        .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()

                        // opcionalno (ako želiš public info)
                        .requestMatchers("/actuator/info").permitAll()

                        // sve ostalo actuatora zaključano
                        .requestMatchers("/actuator/**").hasRole("ADMIN")

                        // business endpoints
                        .requestMatchers("/tasks/**").hasAnyRole("USER", "ADMIN")

                        .anyRequest().authenticated()
                )
                .addFilterBefore(new JwtFilter(jwtService, tokenBlacklistService),
                        UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {

        /*
         * OWASP A07:2025 ZAŠTITA
         * BCrypt strength povećan s default 10 na 12.
         * Otežava offline brute-force napade nad ukradenim hash vrijednostima.
         */
        return new BCryptPasswordEncoder(12);
    }
}