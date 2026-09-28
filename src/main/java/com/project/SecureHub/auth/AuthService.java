package com.project.SecureHub.auth;

import com.project.SecureHub.user.User;
import com.project.SecureHub.user.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailAuthenticationException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

@Service
public class AuthService {
    private final UserRepository users;
    private final PasswordEncoder encoder;
    private final JwtService jwt;
    private final RefreshTokenRepository refreshTokens;
    private final EmailOtpRepository emailOtps;
    private final JavaMailSender mailSender;
    private final String mailFrom;
    private final long otpExpirationMinutes;
    private final SecureRandom random = new SecureRandom();

    public AuthService(
            UserRepository users,
            PasswordEncoder encoder,
            JwtService jwt,
            RefreshTokenRepository refreshTokens,
            EmailOtpRepository emailOtps,
            JavaMailSender mailSender,
            @Value("${app.mail.from:noreply@securehub.local}") String mailFrom,
            @Value("${app.otp.expiration-minutes:5}") long otpExpirationMinutes) {
        this.users = users;
        this.encoder = encoder;
        this.jwt = jwt;
        this.refreshTokens = refreshTokens;
        this.emailOtps = emailOtps;
        this.mailSender = mailSender;
        this.mailFrom = mailFrom;
        this.otpExpirationMinutes = otpExpirationMinutes;
    }

    private String normalizeEmail(String email)
    {
        return email == null ? null : email.trim().toLowerCase();
    }

    public String startRegistration(String email, String password, String displayName)
    {
        String normalized = normalizeEmail(email);
        if (users.findByEmailOrIgnoreCase(normalized).isPresent())
            throw new IllegalArgumentException("Email already registered");

        String otp = generateOtp();
        String otpHash = hashOtp(otp);
        emailOtps.findByEmail(normalized).ifPresent(emailOtps::delete);
        emailOtps.save(new EmailOtp(normalized, otpHash, Instant.now().plusSeconds(otpExpirationMinutes * 60L)));

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(mailFrom);
        message.setTo(normalized);
        message.setSubject("SecureHub email verification");
        message.setText("Your SecureHub verification code is: " + otp + "\n\nThis code will expire in " + otpExpirationMinutes + " minutes.");

        try {
            mailSender.send(message);
        } catch (MailAuthenticationException ex) {
            throw new IllegalStateException(
                    "Gmail SMTP authentication failed. Set MAIL_USERNAME and MAIL_PASSWORD to a valid Gmail account and a Gmail app password (not your regular Gmail password).",
                    ex);
        }

        return otp;
    }

    public User completeRegistration(String email, String otp, String password, String displayName)
    {
        String normalized = normalizeEmail(email);
        EmailOtp pending = emailOtps.findByEmail(normalized)
                .orElseThrow(() -> new IllegalArgumentException("Verification code not requested"));

        if (pending.getExpiresAt().isBefore(Instant.now())) {
            emailOtps.delete(pending);
            throw new IllegalArgumentException("Verification code expired");
        }

        if (!hashOtp(otp).equals(pending.getOtpHash())) {
            throw new IllegalArgumentException("Invalid verification code");
        }

        if (users.findByEmailOrIgnoreCase(normalized).isPresent()) {
            emailOtps.delete(pending);
            throw new IllegalArgumentException("Email already registered");
        }

        emailOtps.delete(pending);
        return users.save(new User(normalized, encoder.encode(password), displayName));
    }

    public User login(String email, String password)
    {
        User user = users.findByEmailOrIgnoreCase(normalizeEmail(email)).orElseThrow(() -> new IllegalArgumentException("Invalid credentials"));
        if (!encoder.matches(password, user.getPasswordHash()))
            throw new IllegalArgumentException("Invalid credentials");
        return user;
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

    private String generateOtp() {
        int otp = 100000 + random.nextInt(900000);
        return String.valueOf(otp);
    }

    private String hashOtp(String otp) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(otp.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to hash OTP", e);
        }
    }

    public record AuthTokens(String accessToken, String refreshToken) {}
}