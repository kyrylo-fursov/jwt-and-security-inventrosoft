package com.example.jwttest;

import static org.junit.jupiter.api.Assertions.*;
import io.jsonwebtoken.Claims;
import com.example.jwttest.entity.UserInfo;
import com.example.jwttest.repository.UserInfoRepository;
import com.example.jwttest.service.JwtService;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@SpringBootTest
public class JwtServiceTest {
    @Mock
    private UserInfoRepository mockRepository;

    @InjectMocks
    private JwtService jwtService;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
        jwtService = new JwtService(mockRepository, "5367566B59703373367639792F423F4528482B4D6251655468576D5A71347437");
    }

    @Test
    void generateAccessTokenTest() {
        String userName = "user";
        Collection<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
        String token = jwtService.generateAccessToken(userName, authorities);
        assertNotNull(token);

        Claims claims = jwtService.extractAllClaims(token);

        // Check that the token's subject matches the username.
        assertEquals(userName, claims.getSubject());

        // Check that the token's authorities are correctly set.
        List<String> tokenAuthorities = claims.get("authorities", List.class);
        assertNotNull(tokenAuthorities);
        assertTrue(tokenAuthorities.contains("ROLE_USER"));

        // Check that the token's expiration is after the current date.
        assertTrue(claims.getExpiration().after(new Date()));
    }

    @Test
    void generateRefreshTokenTest() {
        UserInfo user = new UserInfo(1, "user", "USER_ROLE", "1234", "ROLE_ADMIN");
        String token = jwtService.generateRefreshToken(user);
        assertNotNull(token);

        Claims claims = jwtService.extractAllClaims(token);

        // Check that the token's subject matches the username.
        assertEquals(user.getName(), claims.getSubject());

        // Check that the token's expiration is after the current date.
        assertTrue(claims.getExpiration().after(new Date()));
    }

    @Test
    void extractUsernameTest() {
        String expectedUsername = "user";
        String token = jwtService.generateAccessToken(expectedUsername, List.of());

        String extractedUsername = jwtService.extractUsername(token);

        assertEquals(expectedUsername, extractedUsername);
    }

    @Test
    void validateTokenTest() {
        String userName = "user";
        String validToken = jwtService.generateAccessToken(userName, List.of());
        String invalidToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        String notJwtToken = "not.a.jwt";

        assertTrue(jwtService.validateToken(validToken));
        assertThrows(SignatureException.class, () -> jwtService.validateToken(invalidToken));
        assertThrows(MalformedJwtException.class, () -> jwtService.validateToken(notJwtToken));
    }
}



