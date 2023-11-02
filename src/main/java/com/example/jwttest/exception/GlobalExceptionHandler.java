package com.example.jwttest.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.security.SignatureException;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(SignatureException.class)
    public ResponseEntity<String> handleSignatureException(SignatureException ex) {
        return new ResponseEntity<>("Invalid token", HttpStatus.FORBIDDEN);
    }
}
