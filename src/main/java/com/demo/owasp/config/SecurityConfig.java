package com.demo.owasp.config;

import com.demo.owasp.security.JwtFilter;
import com.demo.owasp.security.JwtService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * OWASP A01:2025 - OBRANA OD NEISPRAVNE KONTROLE PRISTUPA
 * * Ova klasa uspostavlja restriktivan sigurnosni lanac na strani poslužitelja,
 * eliminirajući mogućnost prisilnog pregledavanja (Forced Browsing) i zaobilaženja
 * autorizacijskih provjera kroz klijentsku aplikaciju.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity// Omogućava provjere uloga na razini metoda (@PreAuthorize)
public class SecurityConfig {
    private final JwtService jwtService;
    public SecurityConfig(JwtService jwtService) {
        this.jwtService = jwtService;
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        return http
                .csrf(csrf -> csrf.disable())// CSRF zaštita se rješava naknadno kroz tokene
                .cors(cors -> cors.configurationSource(request -> {
                    var config = new org.springframework.web.cors.CorsConfiguration();
                    // STRKTNO STEZANJE CORS-a: Zabranjeno je korištenje '*' kada se prenose autorizacijski tokeni
                    config.setAllowedOrigins(java.util.List.of("https://trusted-frontend.demo.com"));
                    config.setAllowedMethods(java.util.List.of("GET", "POST", "PUT", "DELETE"));
                    config.setAllowedHeaders(java.util.List.of("Authorization", "Content-Type"));
                    return config;
                }))
                .authorizeHttpRequests(auth -> auth
                        // Rute za registraciju i prijavu su eksplicitno javne
                        .requestMatchers("/auth/**").permitAll()
                        // NAČELO "ZABRANI PO ZADANIM POSTAVKAMA": Sve ostale rute zahtijevaju valjanu autentifikaciju
                        .anyRequest().authenticated()
                )
                // Integracija filtra koji presreće i validira kriptografski potpisane JWT tokene prije izvršenja zahtjeva
                .addFilterBefore(new JwtFilter(jwtService), UsernamePasswordAuthenticationFilter.class) // [cite: 5]
                .build(); // [cite: 5]
    }
}
