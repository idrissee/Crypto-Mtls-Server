package com.crypto.cryotoMtlsServer.services.impl;


import com.crypto.cryotoMtlsServer.services.interfaces.ICertificateUtilsService;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

@Service
@Slf4j
public class CertificateUtilsService implements ICertificateUtilsService {

        @Override
        public String loadCertAsBase64(String certPath) throws IOException {
            Path path = Paths.get(certPath);
            if (!Files.exists(path) || !Files.isRegularFile(path)) {
                log.info("Certificate file not found at path: {}", certPath);
                throw new FileNotFoundException("Certificate file not found: " + certPath);
            }

            byte[] certBytes = Files.readAllBytes(path);
            log.info("Loaded certificate from path: {}", certPath);
            return Base64.getEncoder().encodeToString(certBytes);
        }


    @Override
    public PrivateKey loadPrivateKey(String path) throws Exception {
        Path p = Paths.get(path);
        if (!Files.exists(p) || !Files.isRegularFile(p)) {
            log.info("Private key file not found at path: {}", path);
            throw new FileNotFoundException("Private key file not found: " + path);
        }

        try (Reader reader = Files.newBufferedReader(p);
             PEMParser pemParser = new PEMParser(reader)) {

            Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            switch (object) {
                case null -> throw new IllegalArgumentException("No PEM object found in file: " + path);
                // Unencrypted PKCS#1/PKCS#8 style key pairs
                case PEMKeyPair pemKeyPair -> {
                    log.debug("Loaded PEMKeyPair from file: {}", path);
                    return converter.getPrivateKey(pemKeyPair.getPrivateKeyInfo());
                }
                // Unencrypted PKCS#8 private key info
                case PrivateKeyInfo privateKeyInfo -> {
                    log.debug("Loaded PrivateKeyInfo (PKCS#8) from file: {}", path);
                    return converter.getPrivateKey(privateKeyInfo);
                }
                default -> {
                }
            }
            // Unknown object type
            throw new IllegalArgumentException("Unsupported PEM object in key file: " + path + " (found: " + object.getClass().getName() + ")");
        }
    }


    @Override
    public X509Certificate loadCertificate(String path) throws Exception {
        Path p = Paths.get(path);
        if (!Files.exists(p) || !Files.isRegularFile(p)) {
            log.info("Certificate file not found at path: {}", path);
            throw new FileNotFoundException("Certificate file not found: " + path);
        }

        try (InputStream is = Files.newInputStream(p)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) factory.generateCertificate(is);
            log.debug("Loaded X.509 certificate from file: {}", path);
            return cert;
        }
    }


            @Override
            public String toBase64(X509Certificate cert) throws Exception {
                StringWriter sw = new StringWriter();
                try (JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
                    pemWriter.writeObject(cert);
                }
                return Base64.getEncoder().encodeToString(sw.toString().getBytes());
            }
        }


