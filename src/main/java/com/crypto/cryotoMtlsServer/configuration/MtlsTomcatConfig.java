package com.crypto.cryotoMtlsServer.configuration;

import lombok.RequiredArgsConstructor;
import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.Http11NioProtocol;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class MtlsTomcatConfig {

    private final AppConfig appConfig;

    @Bean
    public TomcatServletWebServerFactory servletContainer() {
        TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory();
        tomcat.addAdditionalTomcatConnectors(createMtlsConnector());
        return tomcat;
    }

    private Connector createMtlsConnector() {
        Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
        connector.setPort(9443); // mTLS port
        Http11NioProtocol protocol = (Http11NioProtocol) connector.getProtocolHandler();

        protocol.setSSLEnabled(true);

        // Create SSL Host Config
        SSLHostConfig sslHostConfig = new SSLHostConfig();
        sslHostConfig.setHostName("_default_");
        sslHostConfig.setCertificateVerification("REQUIRED"); // for mTLS
        sslHostConfig.setTruststoreFile(appConfig.getServer().getTruststorePath());
        sslHostConfig.setTruststorePassword(appConfig.getServer().getTruststorePassword());
        sslHostConfig.setTruststoreType("PKCS12");

        // Keystore for server certificate
        SSLHostConfigCertificate certificate = new SSLHostConfigCertificate(sslHostConfig, SSLHostConfigCertificate.Type.RSA);
        certificate.setCertificateKeystoreFile(appConfig.getServer().getMtlsKeystorePath());
        certificate.setCertificateKeystorePassword(appConfig.getServer().getMtlsKeystorePassword());
        certificate.setCertificateKeystoreType("PKCS12");

        sslHostConfig.addCertificate(certificate);
        protocol.addSslHostConfig(sslHostConfig);

        return connector;
    }
}
