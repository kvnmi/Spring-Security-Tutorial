package com.example.demo.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class JVerifierFilter extends OncePerRequestFilter {

    private final JWTConfig jwtConfig;
    private final SecretKey secretKey;

    public JVerifierFilter(JWTConfig jwtConfig, SecretKey secretKey) {
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var authorization = request.getHeader(jwtConfig.getAuthHeaders());
        if (Strings.isNullOrEmpty(authorization) || !authorization.startsWith(jwtConfig.getTokenPrefix())) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            var token = authorization.replace(jwtConfig.getTokenPrefix(),"");
            var claimsJws = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);
            var username = claimsJws.getBody().getSubject();
            var authorities = (List<Map<String, String>>) claimsJws.getBody().get("authorities");
            var grantedAuthorities = authorities.stream()
                    .map(i -> new SimpleGrantedAuthority(i.get("authority")))
                    .collect(Collectors.toSet());

            var authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    grantedAuthorities
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (JwtException e) {
            throw new IllegalStateException("Token not trusted");
        }
        filterChain.doFilter(request, response);
    }
}
