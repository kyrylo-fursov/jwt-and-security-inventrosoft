package com.example.jwttest.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class TokenRequest {
    private String refreshToken;
    private String username;
}