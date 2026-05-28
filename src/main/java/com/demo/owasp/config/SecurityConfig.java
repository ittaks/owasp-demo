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
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;

import java.util.List;

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
    private final String allowedOrigins;
    // OWASP A02 FIX: CORS domena se ubrizgava iz konfiguracijske datoteke, a ne tvrdo kodirana
    public SecurityConfig(JwtService jwtService, @Value("${app.cors.allowed-origins}") String allowedOrigins) {
        this.jwtService = jwtService;
        this.allowedOrigins = allowedOrigins;
    }
    // OWASP A02: Konfiguracija sigurnog Password Encodera (BCrypt)
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12); // Work factor 12 sprječava brute-force napade
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        return http
                .csrf(csrf -> csrf.disable())// Ako se koristi isključivo stateless JWT, inače ostaviti upaljenokroz tokene
                .cors(cors -> cors.configurationSource(request -> {
                    var config = new org.springframework.web.cors.CorsConfiguration();
                    config.setAllowedOrigins(List.of(allowedOrigins)); // Sigurno učitavanje
                    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
                    config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
                    return config;
                }))
                // OWASP A02: Eksplicitno slanje sigurnosnih direktiva klijentima (Security Headers)
                .headers(headers -> headers
                        .xssProtection(xss -> xss.headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))
                        .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'; frame-ancestors 'none'; object-src 'none';"))
                        .frameOptions(frame -> frame.deny()) // Sprječava Clickjacking
                        .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000))
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**").permitAll()
                        // Dopusti pristup H2 konzoli samo ako je u 'dev' profilu (kontrolirano kroz properties)
                        .requestMatchers("/h2-console/**").permitAll()
                        .anyRequest().authenticated()
                )
                // Ako koristimo H2 konzolu u razvoju, moramo dopustiti sameOrigin za njezine frameove
                .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()))
                .addFilterBefore(new JwtFilter(jwtService), UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    // OWASP A02 FIX: Poseban izolirani lanac koji pali H2 konzolu ISKLJUČIVO na 'dev' profilu
    @Bean
    @Profile("dev")
    @Order(0) // Pokreće se prije glavnog filtera ako je profil aktivan
    public SecurityFilterChain h2ConsoleSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
                .securityMatcher("/h2-console/**")
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .csrf(csrf -> csrf.disable())
                .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin())) // Potrebno za H2 UI
                .build();
    }
}
