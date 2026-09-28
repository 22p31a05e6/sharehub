package com.project.SecureHub.auth;

import com.project.SecureHub.user.User;
import com.project.SecureHub.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mail.MailAuthenticationException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

@SpringBootTest
class AuthRegistrationVerificationTest {
    @Autowired
    private AuthService authService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private EmailOtpRepository emailOtpRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @MockitoBean
    private JavaMailSender mailSender;

    @BeforeEach
    void cleanMailRecords() {
        refreshTokenRepository.deleteAll();
        emailOtpRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    void registrationRequiresOtpBeforeUserIsCreated() {
        String email = "verify-user@example.com";
        String password = "Password123";
        String displayName = "Alice";

        String otp = authService.startRegistration(email, password, displayName);

        ArgumentCaptor<SimpleMailMessage> captor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(captor.capture());
        assertNotNull(captor.getValue().getText());

        assertThrows(IllegalArgumentException.class,
                () -> authService.completeRegistration(email, "000000", password, displayName));

        User created = authService.completeRegistration(email, otp, password, displayName);

        assertEquals(email, created.getEmail());
        assertEquals(displayName, created.getDisplayName());
        assertNotNull(userRepository.findByEmailIgnoreCase(email).orElse(null));
    }

    @Test
    void registrationReportsHelpfulMessageWhenGmailAuthenticationFails() {
        String email = "gmail-auth@example.com";
        doThrow(new MailAuthenticationException("Authentication failed"))
                .when(mailSender).send(org.mockito.ArgumentMatchers.any(SimpleMailMessage.class));

        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> authService.startRegistration(email, "Password123", "Alice"));

        assertTrue(exception.getMessage().contains("Gmail app password"));
    }
}
