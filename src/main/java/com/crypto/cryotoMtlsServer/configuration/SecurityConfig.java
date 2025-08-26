package com.crypto.cryotoMtlsServer.configuration;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
                    // Public endpoint (no mTLS required)
                    .requestMatchers("/tls-establish", "/import-cas" ,"/import-certificates").permitAll()

                    .requestMatchers(
                            "/swagger-ui/**",
                            "/v3/api-docs/**",
                            "/swagger-resources/**",
                            "/webjars/**"
                    ).permitAll()

                    // Protected endpoints (require client cert)
                    .requestMatchers("/protected", "/get-data", "/post-data").authenticated()

                    // Any other endpoints
                    .anyRequest().denyAll()
            )
            // X.509 client certificate authentication
            .x509(x509 -> x509
                    .subjectPrincipalRegex("CN=(.*?)(?:,|$)") // Extract CN from cert subject
                    .userDetailsService(username -> {
                        // For demo: any cert with CN is accepted
                        // Later: you can map CN -> UserDetails for roles
                        return org.springframework.security.core.userdetails.User
                                .withUsername(username)
                                .password("") // not used
                                .authorities("ROLE_USER")
                                .build();
                    })
            );

    return http.build();
}
}
