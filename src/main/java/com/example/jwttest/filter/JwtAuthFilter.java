package com.example.jwttest.filter;

import com.example.jwttest.service.JwtService;
import com.example.jwttest.service.UserInfoService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;


import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    @Autowired
    @Lazy
    private JwtService jwtService;

    @Autowired
    @Lazy
    private UserInfoService userDetailsService;

//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
//            throws ServletException, IOException {
//        String authHeader = request.getHeader("Authorization");
//        String token;
//        String username;
//
//        if (authHeader != null && authHeader.startsWith("Bearer ")) {
//            token = authHeader.substring(7);
//            username = jwtService.extractUsername(token);
//
//            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//                Claims claims = jwtService.extractAllClaims(token);
//                List<GrantedAuthority> authorities = ((List<String>) claims.get("authorities")).stream()
//                        .map(SimpleGrantedAuthority::new)
//                        .collect(Collectors.toList());
//
//                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
//
//                if (jwtService.validateToken(token, userDetails)) {
//                    UsernamePasswordAuthenticationToken authToken =
//                            new UsernamePasswordAuthenticationToken(userDetails, null, authorities);
//                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//                    SecurityContextHolder.getContext().setAuthentication(authToken);
//                }
//            }
//        }
//        filterChain.doFilter(request, response);
//    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");

        try {
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);
                Claims claims = jwtService.extractAllClaims(token);
                String username = claims.getSubject(); // or claims.get("username", String.class)

                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    List<GrantedAuthority> authorities = ((List<String>) claims.get("authorities")).stream()
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList());

                    if (jwtService.validateToken(token)) {
                        UsernamePasswordAuthenticationToken authToken =
                                new UsernamePasswordAuthenticationToken(username, null, authorities);
                        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authToken);
                    }
                }
            }
        } catch (io.jsonwebtoken.SignatureException e) {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.getWriter().write("Invalid token signature");
        return;
        } catch (Exception e) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write("Unauthorized");
        return;
        }
        filterChain.doFilter(request, response);
    }
}