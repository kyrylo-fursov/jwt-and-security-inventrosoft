package com.example.jwttest.csrf;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SubmitController {
    @PostMapping("/submit")
    public ResponseEntity<String> handleSubmit() {
        return new ResponseEntity<>("Form submitted successfully.", HttpStatus.OK);
    }
}
