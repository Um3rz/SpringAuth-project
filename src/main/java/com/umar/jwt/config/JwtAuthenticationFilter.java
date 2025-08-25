package com.umar.jwt.config;
import io.micrometer.common.lang.NonNull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,//has 3 inps
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");//get the auth header
        final String jwt;
        final String userEmail;
        if (authHeader == null || authHeader.startsWith("Bearer ")) {//if no jwt set then move on
           filterChain.doFilter(request, response);
           return;
        }
        jwt= authHeader.substring(7);//get the jwt
        userEmail = jwtService.extractUsername(jwt);//get the email
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);//set the details
            if(jwtService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null,//perform auth
                        userDetails.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetails(request));//set webauth details like user authenticated yes or no
                SecurityContextHolder.getContext().setAuthentication(authToken);//update the security context with the auth token
            }
        }
        filterChain.doFilter(request, response);//pass onto next filter
    }
}
