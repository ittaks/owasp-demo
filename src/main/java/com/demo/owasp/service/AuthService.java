package com.demo.owasp.service;

import com.demo.owasp.dto.request.LoginRequest;
import com.demo.owasp.dto.request.RegisterRequest;
import com.demo.owasp.dto.response.UserResponse;
import com.demo.owasp.entity.User;
import com.demo.owasp.repository.UserRepository;
import com.demo.owasp.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder; // Injektiran siguran encoder

    private UserResponse mapToResponse(User user){
        UserResponse response = new UserResponse();
        response.setId(user.getId());
        response.setUsername(user.getUsername());
        response.setRole(user.getRole());

        return response;
    }

    public UserResponse register(RegisterRequest request) {
        User user = new User();
        user.setUsername(request.getUsername());
        // OWASP A02: Lozinka se više ne sprema u čistom tekstu
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole("USER");

        return mapToResponse(userRepository.save(user));
    }

    public String login(LoginRequest request) {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("Invalid credentials"));

        // OWASP A02: Provjera hashirane lozinke
        if (passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            return jwtService.generateToken(user.getUsername(), user.getRole());
        }

        throw new RuntimeException("Invalid credentials");
    }
}