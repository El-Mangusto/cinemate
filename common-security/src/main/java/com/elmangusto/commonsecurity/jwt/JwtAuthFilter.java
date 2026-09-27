package com.elmangusto.commonsecurity.jwt;

import com.elmangusto.commonsecurity.permission.Permission;
import com.elmangusto.commonsecurity.userdetails.CustomUserDetails;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    public JwtAuthFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        String header = request.getHeader("Authorization");

        if (header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.substring(7);

        if (jwtService.isTokenValid(token)) {
            Claims claims = jwtService.parseClaims(token);

            Long userId = claims.get("userId", Long.class);
            String username = claims.getSubject();

            List<String> rawPermissions = claims.get("permissions", List.class);
            Set<Permission> permissions = rawPermissions.stream()
                    .map(Permission::valueOf)
                    .collect(Collectors.toSet());

            CustomUserDetails principal = new CustomUserDetails(userId, username, permissions);

            var authentication = new UsernamePasswordAuthenticationToken(
                    principal, null, principal.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        filterChain.doFilter(request, response);
    }
}