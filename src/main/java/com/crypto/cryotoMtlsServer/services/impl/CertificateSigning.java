package com.crypto.cryotoMtlsServer.services.impl;

import com.crypto.cryotoMtlsServer.services.interfaces.ICertificateService;
import com.crypto.cryotoMtlsServer.services.interfaces.ICertificateUtilsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;

@Slf4j
@Service
@RequiredArgsConstructor
public class CertificateSigning implements ICertificateService {

    private final ICertificateUtilsService certificateUtilsService;

    @Override
    public X509Certificate signCSR(String csrBase64, String caCertPath, String caKeyPath) throws Exception {
        // Decode CSR
        byte[] csrBytes = Base64.decode(csrBase64);
        PKCS10CertificationRequest csr;
        try (PEMParser pemParser = new PEMParser(new java.io.StringReader(new String(csrBytes, StandardCharsets.UTF_8)))) {
            csr = (PKCS10CertificationRequest) pemParser.readObject();
        }

        // Load CA private key
        PrivateKey caPrivateKey = certificateUtilsService.loadPrivateKey(caKeyPath);
        X509Certificate caCertificate = certificateUtilsService.loadCertificate(caCertPath);

        X500Name issuer = new X500Name(caCertificate.getSubjectX500Principal().getName());
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

        Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60);
        Date notAfter = new Date(System.currentTimeMillis() + (365L * 24 * 60 * 60 * 1000)); // 1 year

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serial,
                notBefore,
                notAfter,
                csr.getSubject(),
                csr.getSubjectPublicKeyInfo()
        );

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier, false,
                extUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));
        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(caCertificate.getPublicKey()));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caPrivateKey);

        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
    }
}
