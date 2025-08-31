package com.crypto.cryotoMtlsServer.configuration;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        // TLS endpoints + Swagger -> only accessible on 8443
                        .requestMatchers(
                                "/tls-establish",
                                "/import-cas",
                                "/import-certificates",
                                "/swagger-ui/**",
                                "/v3/api-docs/**",
                                "/swagger-resources/**",
                                "/webjars/**"
                        ).access((authz, ctx) -> {
                            int port = ctx.getRequest().getLocalPort();
                            return (port == 8443)
                                    ? new AuthorizationDecision(true)
                                    : new AuthorizationDecision(false);
                        })

                        // mTLS endpoints -> only accessible on 9443
                        .requestMatchers(
                                "/protected",
                                "/get-data",
                                "/post-data"
                        ).access((authz, ctx) -> {
                            int port = ctx.getRequest().getLocalPort();
                            return (port == 9443)
                                    ? new AuthorizationDecision(true)
                                    : new AuthorizationDecision(false);
                        })

                        // Everything else is blocked
                        .anyRequest().denyAll()
                );

        return http.build();
    }
}
