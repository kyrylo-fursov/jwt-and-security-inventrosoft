package com.example.jwttest.cors;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/cors")
public class CorsController {
    @GetMapping("/endpointForLocalhost")
    public String localhostEndpoint() {
        return "This is accessible from localhost only.";
    }

    @GetMapping("/endpointForAny")
    public String anyEndpoint() {
        return "This is accessible from any origin.";
    }
}
