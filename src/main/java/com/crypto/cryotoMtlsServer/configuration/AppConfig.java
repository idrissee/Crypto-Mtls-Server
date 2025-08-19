package com.crypto.cryotoMtlsServer.configuration;


import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "app")
@Data
public class AppConfig {

    private Security security;

    @Data
    public static class Security {
        private String mtlsCaCertPath;
        private String mtlsCaKeyPath;
        private String signingCaCertPath;
        private String signingCaKeyPath;
    }
}
