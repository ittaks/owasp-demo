package com.demo.owasp.service;

import com.demo.owasp.dto.request.LoginRequest;
import com.demo.owasp.dto.request.RegisterRequest;
import com.demo.owasp.dto.response.UserResponse;
import com.demo.owasp.entity.User;
import com.demo.owasp.exception.BadCredentialsException;
import com.demo.owasp.repository.UserRepository;
import com.demo.owasp.security.CommonPasswordValidator;
import com.demo.owasp.security.JwtService;
import com.demo.owasp.security.LogSanitizer;
import com.demo.owasp.security.LoginAttemptService;
import com.demo.owasp.security.TokenBlacklistService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final CommonPasswordValidator commonPasswordValidator;
    private final LoginAttemptService loginAttemptService;
    private final TokenBlacklistService tokenBlacklistService;

    private UserResponse mapToResponse(User user){
        UserResponse response = new UserResponse();
        response.setId(user.getId());
        response.setUsername(user.getUsername());
        response.setRole(user.getRole());

        return response;
    }

    public UserResponse register(RegisterRequest request) {

        /*
         * OWASP A07:2025 ZAŠTITA (CWE-1392 Default Credentials)
         *
         * Sprječava registraciju korisničkog računa s već postojećim korisničkim imenom.
         *
         * Time se izbjegavaju:
         * - konflikti identiteta
         * - nepredvidivo ponašanje autentikacije
         */
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new RuntimeException("Registration failed.");
        }

        /*
         * OWASP A07:2025 ZAŠTITA (CWE-521 Weak Password Requirements)
         * Blokiramo najčešće kompromitirane lozinke.
         */
        if (commonPasswordValidator.isWeak(request.getPassword())) {
            throw new RuntimeException("Registration failed.");
        }

        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole("USER");

        return mapToResponse(userRepository.save(user));
    }

    public String login(LoginRequest request) {
        String username = request.getUsername();
        /*
         * OWASP A07:2025 ZAŠTITA
         *
         * Provjera je li račun trenutno zaključan.
         *
         * Namjerno vraćamo istu poruku kao kod
         * neispravnih podataka kako bismo spriječili
         * username enumeration napade.
         */
        if (loginAttemptService.isLocked(username)) {
            String safeUsername = com.demo.owasp.security.LogSanitizer.sanitize(username);
            log.warn("SECURITY ALERT: Pokušaj prijave na zaključani korisnički račun: '{}'. Zahtjev je odbijen.",
                    safeUsername);
            throw new BadCredentialsException("Invalid username or password.");
        }

        User user = userRepository.findByUsername(username).orElseThrow(() -> {
            loginAttemptService.loginFailed(username);
            return new BadCredentialsException("Invalid username or password.");
                });

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            loginAttemptService.loginFailed(username);
            throw new BadCredentialsException("Invalid username or password.");
        }

        /*
         * OWASP A07:2025 ZAŠTITA
         * Uspješna autentikacija resetira brojač.
         */
        loginAttemptService.loginSucceeded(username);
        // [OWASP A09 ZAŠTITA] - Bilježenje uspješne autentifikacije s kontekstom (CWE-778)

        log.info("SECURITY EVENT: Korisnik '{}' se uspješno prijavio u sustav s ulogom: '{}'.", user.getUsername(), user.getRole());

        return jwtService.generateToken(user.getUsername(), user.getRole());
    }

    /*
     * OWASP A07:2025 ZAŠTITA
     *
     * Opoziv JWT tokena nakon odjave.
     *
     * Time sprječavamo korištenje
     * već kompromitiranih tokena.
     */
    public void logout(HttpServletRequest request) {
        String header = request.getHeader("Authorization");

        if (header == null || !header.startsWith("Bearer ")) {
            return;
        }

        String token = header.substring(7);

        String tokenId = jwtService.extractTokenId(token);
        Instant expiry = jwtService.extractExpiration(token).toInstant();

        // [OWASP A09 ZAŠTITA] - Praćenje opoziva sesija
        log.info("SECURITY EVENT: Korisnik s tokenom ID '{}' se uspješno odjavio. Token je dodan na crnu listu.", tokenId);

        jwtService.deactivateToken(tokenId);
        tokenBlacklistService.blacklist(tokenId, expiry);
    }
}