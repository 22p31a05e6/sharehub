package com.project.SecureHub.auth;


import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;
import java.security.MessageDigest;
import java.util.HexFormat;

@Service
public class JwtService {
    private final SecretKey key;
    private final long expiration;
    public JwtService(
            @Value("${app.jwt.secret}") String secret,
            @Value("${app.jwt.expiration-ms}") long expiration)
    {
        key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)); this.expiration = expiration;
    }
    public String create(String email)
    {
        return Jwts.builder().subject(email).issuedAt(new Date()).expiration(new Date(System.currentTimeMillis()+expiration)).signWith(key).compact();
    }
    public String subject(String token)
    {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload().getSubject();
    }
    public String createRefreshToken()
    {
        return UUID.randomUUID() + "." + UUID.randomUUID();
    }
    public String hashRefreshToken(String token)
    {
        try
        {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
        }
        catch (Exception exception)
        {
            throw new IllegalStateException(exception);
        }
    }
    public long refreshLifetime()
    {
        return expiration * 8;
    }
}

