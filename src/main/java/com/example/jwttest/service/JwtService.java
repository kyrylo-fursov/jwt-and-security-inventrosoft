package com.example.jwttest.service;

import com.example.jwttest.entity.UserInfo;
import com.example.jwttest.repository.TokenRepository;
import com.example.jwttest.repository.UserInfoRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class JwtService {
    private final UserInfoRepository repository;
    private final UserInfoService userInfoService;
    public static final String SECRET = "5367566B59703373367639792F423F4528482B4D6251655468576D5A71347437";

    public JwtService(UserInfoRepository repository, UserInfoService userInfoService) {
        this.repository = repository;
        this.userInfoService = userInfoService;
    }

    public String generateAccessToken(String userName, Collection<? extends GrantedAuthority> authorities) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", userName);
        claims.put("authorities", authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));
        return createToken(claims, userName);
    }

    public List<GrantedAuthority> getAuthoritiesByUsername(String username) {
        Optional<UserInfo> userInfo = repository.findByName(username);
        if (userInfo.isPresent()) {
            String roles = userInfo.get().getRoles();
            return Arrays.stream(roles.split(","))
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        }
        throw new UsernameNotFoundException("User not found: " + username);
    }

    public String generateRefreshToken(UserInfo user) {
        String userName = user.getName();
        List<GrantedAuthority> authorities = userInfoService.getAuthoritiesByUsername(userName);
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", userName);
        claims.put("authorities", authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));
        return createRefreshToken(claims, userName);
    }

    private String createRefreshToken(Map<String, Object> claims, String username) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24 * 7))
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
    }

    public String generateAccessTokenFromRefreshToken(String oldRefreshToken) {
        // Extract user info from the old refresh token
        String username = extractUsername(oldRefreshToken);
        // Assuming you have a method to get authorities based on username
        Collection<? extends GrantedAuthority> authorities = getAuthorities(username);
        // Create a new access token
        return generateAccessToken(username, authorities);
    }

    // A hypothetical method to get authorities; you would typically fetch this from your data store
    private Collection<? extends GrantedAuthority> getAuthorities(String username) {
        // Fetch the authorities based on username
        // For demonstration purposes, returning a hardcoded list
        return List.of(new SimpleGrantedAuthority("ROLE_USER"));
    }

    private String createToken(Map<String, Object> claims, String userName) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userName)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 30))
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
    }

    private Key getSignKey() {
        byte[] keyBytes= Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
