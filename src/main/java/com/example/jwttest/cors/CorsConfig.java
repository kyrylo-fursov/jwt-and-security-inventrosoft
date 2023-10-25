package com.example.jwttest.cors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.Arrays;
import java.util.List;

@Configuration
public class CorsConfig implements WebMvcConfigurer {

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration localhostConfig = new CorsConfiguration();
        localhostConfig.setAllowedOriginPatterns(List.of("http://localhost:*"));
        localhostConfig.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        localhostConfig.setAllowedHeaders(Arrays.asList("*"));
        localhostConfig.setAllowCredentials(true);

        CorsConfiguration anyConfig = new CorsConfiguration();
        anyConfig.setAllowedOrigins(Arrays.asList("*"));
        anyConfig.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        anyConfig.setAllowedHeaders(Arrays.asList("*"));
        anyConfig.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/endpointForLocalhost", localhostConfig);
        source.registerCorsConfiguration("/endpointForAny", anyConfig);

        return source;
    }
}
