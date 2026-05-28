package com.demo.owasp.config;

import com.demo.owasp.security.JwtFilter;
import com.demo.owasp.security.JwtService;
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
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtService jwtService;
    private final String allowedOrigins;

    public SecurityConfig(JwtService jwtService, @Value("${app.cors.allowed-origins}") String allowedOrigins) {
        this.jwtService = jwtService;
        this.allowedOrigins = allowedOrigins;
    }

    // =========================================================================
    // OWASP A02: IZOLIRANI LANAC ZA H2 KONZOLU (Aktivno ISKLJUČIVO na 'dev' profilu)
    // =========================================================================
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

    // =========================================================================
    // GLAVNI SIGURNOSNI LANAC APLIKACIJE (Sadrži OWASP A01, A02, A04 zaštitu)
    // =========================================================================
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
                // -----------------------------------------------------------------
                // OWASP A04: HARDENING TRANSPORTNOG SLOJA I SPREČAVANJE CURENJA PODATAKA
                // -----------------------------------------------------------------
                .headers(headers -> headers
                        // 1. Aktivacija HSTS-a (HTTP Strict Transport Security) -> Rješava CWE-319, CWE-523
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(31536000) // Prisila na HTTPS u trajanju od 1 godine
                        )
                        // 2. Eksplicitna zabrana predmemoriranja (Cache Control) -> Rješava CWE-523 curenje iz preglednika
                        .cacheControl(cache -> {})
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(new JwtFilter(jwtService), UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    // OWASP A04 & A02 HASHING: Adaptivno i soljeno sažimanje lozinki (BCrypt sa CSPRNG) -> Rješava CWE-916
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}