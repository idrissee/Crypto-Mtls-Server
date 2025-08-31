package com.crypto.cryotoMtlsServer.configuration;


import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class SwaggerConfig {

    @Value("${api.openapi.tls-url}")
    private String devUrl;

    @Value("${api.openapi.mtls-url}")
    private String mtlsUrl;

    @Bean
    public OpenAPI myOpenAPI() {
        SecurityScheme mtlsScheme = new SecurityScheme()
                .type(SecurityScheme.Type.MUTUALTLS)
                .description("mTLS authentication required. Provide a client certificate issued by the MTLS Root CA.");

        Server tlsServer = new Server();
        tlsServer.setUrl(devUrl);
        tlsServer.setDescription("TLS server (8443) for public endpoints");

        Server mtlsServer = new Server();
        mtlsServer.setUrl(mtlsUrl);
        mtlsServer.setDescription("mTLS server (9443) for protected endpoints (requires client cert)");

        Contact contact = new Contact()
                .email("mahieddineidris.cheriet@gmail.com")
                .name("Idris");

        Info info = new Info()
                .title("Crypto mTLS Server API")
                .version("1.0")
                .contact(contact)
                .description("Demo API with TLS & mTLS separation");

        return new OpenAPI().
                info(info)
                .servers(List.of(tlsServer, mtlsServer))
                .schemaRequirement("mtls", mtlsScheme);
    }

}
