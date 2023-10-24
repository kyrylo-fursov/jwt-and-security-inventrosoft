package com.example.jwttest.controller;

import com.example.jwttest.entity.AuthRequest;
import com.example.jwttest.entity.RefreshTokenEntity;
import com.example.jwttest.entity.TokenRequest;
import com.example.jwttest.entity.TokenResponse;
import com.example.jwttest.entity.UserInfo;
import com.example.jwttest.repository.TokenRepository;
import com.example.jwttest.service.JwtService;
import com.example.jwttest.service.UserInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Collection;

@RestController
@RequestMapping("/auth")
public class UserController {

    @Autowired
    private UserInfoService service;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private TokenRepository tokenRepository;

    @GetMapping("/welcome")
    public String welcome() {
        System.out.println("welcome endpoint"); // TODO: remove this line
        return "Welcome this endpoint is not secure";
    }

    @PostMapping("/addNewUser")
    public String addNewUser(@RequestBody UserInfo userInfo) {
        System.out.println("trying to add new user : " + userInfo); // TODO: remove this line
        return service.addUser(userInfo);
    }

    @PostMapping("/createToken")
    public TokenResponse createToken(@RequestBody AuthRequest authRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));

        if (authentication.isAuthenticated()) {
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
            String accessToken = jwtService.generateAccessToken(authRequest.getUsername(), authorities);

            // Generate refresh token
            UserInfo user = service.loadUserInfoByUsername(authRequest.getUsername());
            String refreshToken = jwtService.generateRefreshToken(user);

            // Store the refresh token
            tokenRepository.save(new RefreshTokenEntity(user, refreshToken));
            return new TokenResponse(accessToken, refreshToken);
        } else {
            throw new UsernameNotFoundException("Invalid user request!");
        }
    }

    @PostMapping("/refreshToken")
    public TokenResponse refreshToken(@RequestBody TokenRequest tokenRequest) throws Exception {
        String oldRefreshToken = tokenRequest.getRefreshToken();

        // Validate and remove the old refresh token from the database
        if (tokenRepository.validateAndRemove(oldRefreshToken)) {
            String newAccessToken = jwtService.generateAccessTokenFromRefreshToken(oldRefreshToken);
            UserInfo user = service.loadUserInfoByUsername(tokenRequest.getUsername());
            String newRefreshToken = jwtService.generateRefreshToken(user);
            // Store the new refresh token in  database and map it to the user
            tokenRepository.save(new RefreshTokenEntity(user, newRefreshToken));

            return new TokenResponse(newAccessToken, newRefreshToken);
        } else {
            throw new Exception("Invalid refresh token!");
        }
    }

    @GetMapping("/user/userProfile")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public String userProfile() {
        return "Welcome to User Profile";
    }

    @GetMapping("/admin/adminProfile")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String adminProfile() {
        return "Welcome to Admin Profile";
    }
}
