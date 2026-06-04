package com.demo.owasp.controller;

import com.demo.owasp.dto.request.LoginRequest;
import com.demo.owasp.dto.request.RegisterRequest;
import com.demo.owasp.dto.response.UserResponse;
import com.demo.owasp.entity.User;
import com.demo.owasp.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@RequestBody RegisterRequest request) {
        UserResponse response = authService.register(request);
        return ResponseEntity.ok(response);
    }

    /**
     * OWASP A01 DEFENSEa
     *
     * client sada dobiva TOKEN
     * i koristi ga u Authorization headeru
     */
    @PostMapping("/login")
    public String login(@RequestBody LoginRequest request) {

        return authService.login(request);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request) {
        authService.logout(request);
        return ResponseEntity.noContent().build();
    }

}