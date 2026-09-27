package com.project.SecureHub.auth;



import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController @RequestMapping("/api/auth")
public class AuthController {
    private final AuthService auth;
    public AuthController(AuthService auth)
    {
        this.auth = auth;
    }
    public record AuthRequest(@Email @NotBlank String email, @Size(min=8) String password, String displayName) {}
    public record AuthResponse(String token, String refreshToken, String email, String displayName) {}
    public record RefreshRequest(@NotBlank String refreshToken) {}
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    AuthResponse register(@Valid @RequestBody AuthRequest request)
    {
        return response(auth.register(request.email(), request.password(), request.displayName()));
    }
    @PostMapping("/login")
    AuthResponse login(@Valid @RequestBody AuthRequest request)
    {
        return response(auth.login(request.email(), request.password()));
    }
    @PostMapping("/refresh")
    AuthResponse refresh(@Valid @RequestBody RefreshRequest request)
    {
        return response(auth.refresh(request.refreshToken()));
    }
    @PostMapping("/logout")
    void logout(@Valid @RequestBody RefreshRequest request)
    {
        auth.logout(request.refreshToken());
    }
    private AuthResponse response(com.project.SecureHub.user.User user)
    {   AuthService.AuthTokens tokens = auth.tokens(user);
        return new AuthResponse(tokens.accessToken(), tokens.refreshToken(), user.getEmail(), user.getDisplayName());
    }
}
