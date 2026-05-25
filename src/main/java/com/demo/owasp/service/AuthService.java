package com.demo.owasp.service;

import com.demo.owasp.dto.request.LoginRequest;
import com.demo.owasp.dto.request.RegisterRequest;
import com.demo.owasp.dto.response.UserResponse;
import com.demo.owasp.entity.User;
import com.demo.owasp.repository.UserRepository;
import com.demo.owasp.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;

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
        user.setPassword(request.getPassword()); // plain text
        user.setRole("USER");

        return mapToResponse(userRepository.save(user));
    }

    /**
     * OWASP A01 DEFENSE
     *
     * PRIJE:
     * - vraćao User objekt → leak + nema kontrole
     *
     * SADA:
     * - vraćamo JWT
     * - client više NE upravlja identitetom
     */
    public String login(LoginRequest request) {

        // 1. Cleanly unpack the Optional. If empty, throw a generic message immediately.
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("Invalid credentials"));

        // 2. If the user is found, safely verify the password.
        if (user.getPassword().equals(request.getPassword())) {
            // 3. Generate the signed cryptographically-secure JWT token
            return jwtService.generateToken(user.getUsername(), user.getRole());
        }

        // 4. Throw the exact same generic message if the password fails.
        throw new RuntimeException("Invalid credentials");
    }
}