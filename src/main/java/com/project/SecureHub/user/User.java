package com.project.SecureHub.user;
import jakarta.persistence.*;
import java.util.UUID;

@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    @Column(nullable = false, unique = true)
    private String email;
    @Column(nullable = false)
    private String passwordHash;
    @Column(nullable = false)
    private String displayName;
    protected User() {}
    public User(String email, String passwordHash, String displayName)
    {   this.email=email;
        this.passwordHash=passwordHash;
        this.displayName=displayName;
    }
    public UUID getId()
    {
        return id;
    }
    public String getEmail()
    {
        return email;
    }
    public String getPasswordHash()
    {
        return passwordHash;
    }
    public String getDisplayName()
    {
        return displayName;
    }
}