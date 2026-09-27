package com.project.SecureHub.auth;



import com.project.SecureHub.user.User;
import com.project.SecureHub.user.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
public class AuthService {
    private final UserRepository users;
    private final PasswordEncoder encoder;
    private final JwtService jwt;
    private final RefreshTokenRepository refreshTokens;
    public AuthService(UserRepository users, PasswordEncoder encoder, JwtService jwt, RefreshTokenRepository refreshTokens)
    {   this.users = users;
        this.encoder = encoder;
        this.jwt = jwt;
        this.refreshTokens = refreshTokens;
    }
    private String normalizeEmail(String email)
    {
        return email == null ? null : email.trim().toLowerCase();
    }
    public User register(String email, String password, String displayName)
    {
        String normalized = normalizeEmail(email);
        if (users.findByEmailOrIgnoreCase(normalized).isPresent())
            throw new IllegalArgumentException("Email already registered");
        return users.save(new User(normalized, encoder.encode(password), displayName));
    }
    public User login(String email, String password)
    {
        User user = users.findByEmailOrIgnoreCase(normalizeEmail(email)).orElseThrow(() -> new IllegalArgumentException("Invalid credentials"));
        if (!encoder.matches(password, user.getPasswordHash()))
            throw new IllegalArgumentException("Invalid credentials");
        return user;
    }
    public User oauthUser(String email, String displayName)
    {
        String normalized = normalizeEmail(email);
        return users.findByEmailOrIgnoreCase(normalized).orElseGet(() -> users.save(new User(normalized, encoder.encode(UUID.randomUUID().toString()), displayName)));
    }
    public AuthTokens tokens(User user)
    {
        String refresh = jwt.createRefreshToken();
        refreshTokens.save(new RefreshToken(jwt.hashRefreshToken(refresh), user, Instant.now().plusMillis(jwt.refreshLifetime())));
        return new AuthTokens(jwt.create(user.getEmail()), refresh);
    }
    public User refresh(String rawToken)
    {
        RefreshToken stored = refreshTokens.findByTokenHash(jwt.hashRefreshToken(rawToken)).filter(token -> !token.isRevoked() && token.getExpiresAt().isAfter(Instant.now())).orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));
        stored.revoke();
        refreshTokens.save(stored);
        return stored.getUser();
    }
    public void logout(String rawToken)
    {
        refreshTokens.findByTokenHash(jwt.hashRefreshToken(rawToken)).ifPresent(token -> {
            token.revoke();
            refreshTokens.save(token);
        });
    }
    public record AuthTokens(String accessToken, String refreshToken) {}
}