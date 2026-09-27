package com.project.SecureHub.user;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {
    Optional<User> findByEmailIgnoreCase(String email);
    Optional<User> findByEmail(String email);

    default Optional<User> findByEmailOrIgnoreCase(String email) {
        String normalized = email == null ? null : email.trim();
        return findByEmailIgnoreCase(normalized).or(() -> findByEmail(normalized));
    }
}
