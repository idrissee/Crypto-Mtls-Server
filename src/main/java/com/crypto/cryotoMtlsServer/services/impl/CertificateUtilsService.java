package com.crypto.cryotoMtlsServer.services.impl;


import com.crypto.cryotoMtlsServer.services.interfaces.ICertificateUtilsService;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.springframework.stereotype.Service;

import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

@Service
@Slf4j
public class CertificateUtilsService implements ICertificateUtilsService {

        @Override
        public String loadCertAsBase64(String certPath) throws IOException {
            try (InputStream inputStream = CertificateUtilsService.class.getClassLoader().getResourceAsStream(certPath)) {
                if (inputStream == null) {
                    log.info("Certificate not found");
                    throw new IOException("Certificate not found: " + certPath);
                }
                byte[] certBytes = inputStream.readAllBytes();
                log.info("Certificate loaded");
                return Base64.getEncoder().encodeToString(certBytes);
            }
        }
            @Override
            public PrivateKey loadPrivateKey(String path) throws Exception {
                try (PEMParser pemParser = new PEMParser(new FileReader(path))) {
                    Object object = pemParser.readObject();
                    JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

                    if (object instanceof org.bouncycastle.openssl.PEMKeyPair) {
                        // PKCS#1 (RSA style)
                        return converter.getPrivateKey(((org.bouncycastle.openssl.PEMKeyPair) object).getPrivateKeyInfo());
                    } else if (object instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo) {
                        // PKCS#8
                        return converter.getPrivateKey((org.bouncycastle.asn1.pkcs.PrivateKeyInfo) object);
                    } else {
                        throw new IllegalArgumentException("Unsupported key format in file: " + path);
                    }
                }
            }
            @Override
            public X509Certificate loadCertificate(String path) throws Exception {
                try (FileReader reader = new FileReader(path)) {
                    CertificateFactory factory = CertificateFactory.getInstance("X.509");
                    return (X509Certificate) factory.generateCertificate(new java.io.FileInputStream(path));
                }
            }


            @Override
            public String toBase64(X509Certificate cert) throws Exception {
                StringWriter sw = new StringWriter();
                try (JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
                    pemWriter.writeObject(cert);
                }
                return java.util.Base64.getEncoder().encodeToString(sw.toString().getBytes());
            }
        }


