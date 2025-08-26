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

    @Value("${api.openapi.dev-url}")
    private String devUrl;

//    @Value("${api.openapi.prod-url}")
//    private String prodUrl;

    @Bean
    public OpenAPI myOpenAPI() {

        // Define client certificate auth scheme (MTLS)
        SecurityScheme mtlsScheme = new SecurityScheme()
                .type(SecurityScheme.Type.MUTUALTLS)
                .description("Provide client certificate for mTLS");

        Server devServer = new Server();
        devServer.setUrl(devUrl);
        devServer.setDescription(" Crypto-MTLS Server (Development)");

//        Server prodServer = new Server();
//        prodServer.setUrl(prodUrl);
//        prodServer.setDescription("Crypto-MTLS Server (Production)");

        Contact contact = new Contact();
                contact.setEmail("mahieddineidris.cheriet@gmail.com");
                contact.setName("Idris");

//        License license = new License()
//                .name("Apache 2.0")
//                .url("http://www.apache.org/licenses/LICENSE-2.0.html");

        return new OpenAPI()
                .info(new Info()
                        .title("Crypto-MTLS Server API")
                        .version("1.0")
                        .contact(contact)
                        .description("API endpoints for TLS and mutual TLS testing."))
                .servers(List.of(devServer))
                .schemaRequirement("mtls", mtlsScheme);
    }
}
