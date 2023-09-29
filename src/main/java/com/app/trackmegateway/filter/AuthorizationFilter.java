package com.app.trackmegateway.filter;

import io.jsonwebtoken.*;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Objects;

@Slf4j
@Component
public class AuthorizationFilter extends AbstractGatewayFilterFactory<AuthorizationFilter.Config> {

    private final Environment env;

    @Autowired
    public AuthorizationFilter(Environment env) {
        super(Config.class);
        this.env = env;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            if (!checkAuthorization(request)) {
                return onError(exchange, "No authorization header", HttpStatus.UNAUTHORIZED);
            } else if (Objects.nonNull(request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0)) // 디버그 모드인 경우
                    && request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0).equals(env.getProperty("authorization.debug_key"))) {
                return chain.filter(exchange);
            }

            // Bearer Token 검증
            String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            String jwt = authorizationHeader.replace("Bearer", "").trim();
            if (!isJwtValid(jwt)) {
                return onError(exchange, "JWT is not valid", HttpStatus.UNAUTHORIZED);
            }
            return chain.filter(exchange);
        };
    }

    private boolean isJwtValid(String jwt) {
        boolean isValid = true;
        String subject = null;

        try {
            subject = Jwts.parser().setSigningKey(env.getProperty("jwt.secret_key").getBytes())
                    .parseClaimsJws(jwt).getBody()
                    .getSubject();
        } catch (Exception e) {
            isValid = false;
        }

        if (subject == null || subject.isEmpty()) {
            isValid = false;
        }
        return isValid;
    }

    private boolean checkAuthorization(ServerHttpRequest request) {
        String authorizationHeader = Objects.requireNonNull(request.getHeaders().get(HttpHeaders.AUTHORIZATION)).get(0);
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer"))
            return false;
        return true;
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        log.error(err);
        return response.setComplete();
    }

    @Data
    public static class Config {
        // Put the configuration properties
        private String baseMessage;
        private boolean preLogger;
        private boolean postLogger;
    }
}
