package com.bookmgmt.gateway;



import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    SecurityWebFilterChain filterChain(ServerHttpSecurity http, @Value("${app.jwt.secret}") String secret) {
        return http
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .cors(Customizer.withDefaults())
            .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
            .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
            .securityContextRepository(NoOpServerSecurityContextRepository.getInstance()) // stateless
            .exceptionHandling(e -> e.authenticationEntryPoint(new HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED)))
            .authorizeExchange(auth -> auth
                .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .pathMatchers("/api/auth/**").permitAll()
                .pathMatchers("/internal/**").denyAll()          // service-to-service only, never public
                .pathMatchers("/api/admin/**").hasRole("ADMIN")
                .pathMatchers(HttpMethod.GET, "/api/books/**").hasAnyRole("USER", "ADMIN")
                .pathMatchers(HttpMethod.POST, "/api/books/**").hasRole("ADMIN")
                .pathMatchers(HttpMethod.PUT, "/api/books/**").hasRole("ADMIN")
                .pathMatchers(HttpMethod.DELETE, "/api/books/**").hasRole("ADMIN")
                .anyExchange().authenticated())
            .addFilterAt(new JwtAuthWebFilter(secret), SecurityWebFiltersOrder.AUTHENTICATION)
            .build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration c = new CorsConfiguration();
        c.setAllowedOrigins(List.of("http://localhost:4200", "http://localhost:5173"));
        c.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        c.setAllowedHeaders(List.of("*"));
        c.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", c);
        return source;
    }
}