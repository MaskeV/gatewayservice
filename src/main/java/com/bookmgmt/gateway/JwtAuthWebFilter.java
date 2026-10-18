package com.bookmgmt.gateway;


import java.nio.charset.StandardCharsets;
import java.net.URLEncoder;
import java.util.List;
import javax.crypto.SecretKey;

import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

// NOT a @Component: it is created in SecurityConfig, otherwise Spring would run it twice
public class JwtAuthWebFilter implements WebFilter {

    private final SecretKey key;

    public JwtAuthWebFilter(String secret) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        // never trust identity headers sent by the client, only the ones we set below
        ServerHttpRequest.Builder request = exchange.getRequest().mutate().headers(h -> {
            h.remove("X-User-Email");
            h.remove("X-User-Role");
            h.remove("X-User-Name");
        });

        String header = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith("Bearer ")) {
            return chain.filter(exchange.mutate().request(request.build()).build());
        }

        try {
            Claims c = Jwts.parser().verifyWith(key).build()
                    .parseSignedClaims(header.substring(7)).getPayload();
            String email = c.getSubject();
            String role = c.get("role", String.class);
            String name = c.get("name", String.class);

            var auth = new UsernamePasswordAuthenticationToken(
                    email, null, List.of(new SimpleGrantedAuthority("ROLE_" + role)));

            request.header("X-User-Email", email)
                   .header("X-User-Role", role)
                   .header("X-User-Name", name == null ? "" : URLEncoder.encode(name, StandardCharsets.UTF_8));

            return chain.filter(exchange.mutate().request(request.build()).build())
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
        } catch (JwtException | IllegalArgumentException e) {
            // bad or expired token: continue unauthenticated, the rules below answer 401
            return chain.filter(exchange.mutate().request(request.build()).build());
        }
    }
}