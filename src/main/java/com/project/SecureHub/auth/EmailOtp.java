package com.project.SecureHub.auth;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "email_otps")
public class EmailOtp {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false, length = 64)
    private String otpHash;

    @Column(nullable = false)
    private Instant expiresAt;

    protected EmailOtp() {}

    public EmailOtp(String email, String otpHash, Instant expiresAt) {
        this.email = email;
        this.otpHash = otpHash;
        this.expiresAt = expiresAt;
    }

    public UUID getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public String getOtpHash() {
        return otpHash;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }
}
