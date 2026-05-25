package com.demo.owasp.repository;

import com.demo.owasp.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    // A01 DEMONSTRATION: Restricts data matching context layers to a specific user primary key
    Optional<User> findByUsername(String username);
}
