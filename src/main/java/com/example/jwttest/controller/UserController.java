package com.example.jwttest.controller;

import com.example.jwttest.entity.AuthRequest;
import com.example.jwttest.entity.RefreshTokenEntity;
import com.example.jwttest.entity.TokenRequest;
import com.example.jwttest.entity.TokenResponse;
import com.example.jwttest.entity.UserInfo;
import com.example.jwttest.exception.InvalidTokenException;
import com.example.jwttest.repository.RefreshTokenRepository;
import com.example.jwttest.service.JwtService;
import com.example.jwttest.service.UserInfoService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class UserController {
    private final UserInfoService userInfoService;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;

    public UserController(RefreshTokenRepository refreshTokenRepository,
                          AuthenticationManager authenticationManager,
                          JwtService jwtService,
                          UserInfoService userInfoService) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.userInfoService = userInfoService;
    }

    @GetMapping("/welcome")
    public ResponseEntity<String> welcome() {
        return new ResponseEntity<>("Welcome, this endpoint is not secure", HttpStatus.OK);
    }

    @PostMapping("/register")
    public ResponseEntity<String> addNewUser(@RequestBody UserInfo userInfo) {
        String result = userInfoService.addUser(userInfo);
        if (result != null) {
            return new ResponseEntity<>(result, HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>("User could not be created", HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> createToken(@RequestBody AuthRequest authRequest) {
        try {
            UserInfo user = userInfoService.loadUserInfoByUsername(authRequest.getUsername());
            Authentication authentication = authenticateUser(authRequest);
            String accessToken = generateAccessToken(authentication, authRequest);
            String refreshToken = generateRefreshToken(user);
            saveRefreshToken(refreshToken, user);
            return new ResponseEntity<>(new TokenResponse(accessToken, refreshToken), HttpStatus.OK);
        } catch (AuthenticationException e) {
            return new ResponseEntity<>(null, HttpStatus.UNAUTHORIZED);
        }
    }

    private Authentication authenticateUser(AuthRequest authRequest) {
        return authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
    }

    private String generateAccessToken(Authentication authentication, AuthRequest authRequest) {
        return jwtService.generateAccessToken(authRequest.getUsername(), authentication.getAuthorities());
    }

    private String generateRefreshToken(UserInfo user) {
        return jwtService.generateRefreshToken(user);
    }

    private void saveRefreshToken(String refreshToken, UserInfo user) {
        refreshTokenRepository.deleteByUser(user);
        refreshTokenRepository.save(new RefreshTokenEntity(user, refreshToken));
    }

    @PostMapping("/refreshToken")
    public ResponseEntity<?> refreshToken(@RequestBody TokenRequest tokenRequest) {
        try {
            // Validate and remove old token
            UserInfo userFromDB = getUserByToken(tokenRequest.getRefreshToken());
            validateUser(userFromDB, tokenRequest);
            removeToken(tokenRequest.getRefreshToken());

            // Generate new tokens
            UserInfo user = userInfoService.loadUserInfoByUsername(tokenRequest.getUsername());
            String newAccessToken = generateAccessTokenFromRefreshToken(tokenRequest);
            String newRefreshToken = generateRefreshToken(user);
            saveNewRefreshToken(newRefreshToken, user);

            return ResponseEntity.ok(new TokenResponse(newAccessToken, newRefreshToken));
        } catch (InvalidTokenException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    private UserInfo getUserByToken(String refreshToken) throws InvalidTokenException {
        UserInfo userFromDB = refreshTokenRepository.findUserByToken(refreshToken);
        if (userFromDB == null) {
            throw new InvalidTokenException("Invalid refresh token");
        }
        return userFromDB;
    }

    private void validateUser(UserInfo userFromDB, TokenRequest tokenRequest) throws InvalidTokenException {
        if (!userFromDB.getName().equals(tokenRequest.getUsername())) {
            throw new InvalidTokenException("User mismatch or invalid token");
        }
    }

    private void removeToken(String refreshToken) throws InvalidTokenException {
        boolean isValid = refreshTokenRepository.validateAndRemove(refreshToken);
        if (!isValid) {
            throw new InvalidTokenException("Invalid refresh token");
        }
    }

    private String generateAccessTokenFromRefreshToken(TokenRequest tokenRequest) {
        return jwtService.generateAccessTokenFromRefreshToken(tokenRequest.getRefreshToken());
    }


    private void saveNewRefreshToken(String newRefreshToken, UserInfo user) {
        refreshTokenRepository.save(new RefreshTokenEntity(user, newRefreshToken));
    }


    @GetMapping("/user/userProfile")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public ResponseEntity<String> userProfile() {
        return new ResponseEntity<>("Welcome to User Profile", HttpStatus.OK);
    }

    @GetMapping("/admin/adminProfile")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<String> adminProfile() {
        return new ResponseEntity<>("Welcome to Admin Profile", HttpStatus.OK);
    }
}
