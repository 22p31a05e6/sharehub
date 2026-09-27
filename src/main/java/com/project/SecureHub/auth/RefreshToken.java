package com.project.SecureHub.auth;



import com.project.SecureHub.user.User;
import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "refresh_tokens")
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    @Column(nullable = false, unique = true, length = 64)
    private String tokenHash;
    @ManyToOne(optional = false)
    private User user;
    @Column(nullable = false)
    private Instant expiresAt;
    @Column(nullable = false)
    private boolean revoked;
    protected RefreshToken() {}
    public RefreshToken(String tokenHash, User user, Instant expiresAt)
    {   this.tokenHash = tokenHash;
        this.user = user;
        this.expiresAt = expiresAt;
    }
    public String getTokenHash()
    {
        return tokenHash;
    }
    public User getUser()
    {
        return user;
    }
    public Instant getExpiresAt()
    {
        return expiresAt;
    }
    public boolean isRevoked()
    {
        return revoked;
    }
    public void revoke()
    {
        revoked = true;
    }
}