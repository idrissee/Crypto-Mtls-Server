package com.crypto.cryotoMtlsServer.services.impl;


import com.crypto.cryotoMtlsServer.configuration.AppConfig;
import com.crypto.cryotoMtlsServer.exceptions.CertNotTrustedException;
import com.crypto.cryotoMtlsServer.exceptions.ChallengeNotFoundException;
import com.crypto.cryotoMtlsServer.exceptions.MissingCertificateException;
import com.crypto.cryotoMtlsServer.exceptions.SignatureNotValidException;
import com.crypto.cryotoMtlsServer.model.domain.Challenge;
import com.crypto.cryotoMtlsServer.model.dtos.PostDataRequest;
import com.crypto.cryotoMtlsServer.services.interfaces.ICertificateUtilsService;
import com.crypto.cryotoMtlsServer.services.interfaces.IChallengeService;
import com.crypto.cryotoMtlsServer.services.interfaces.ISignatureService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import java.security.Signature;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.security.cert.*;
import java.util.Base64;
import java.util.Collections;

@Service
@Slf4j
@RequiredArgsConstructor
public class SignatureService implements ISignatureService {

    private final IChallengeService challengeService;
    private final ICertificateUtilsService certificateUtilsService;
    private final AppConfig appConfig;


    @Override
    public void verfiyChallengeData(X509Certificate[] peerCerts, PostDataRequest request) throws Exception {

        log.info("Starting challenge verification process...");

        if (peerCerts == null || peerCerts.length == 0) {
            throw new MissingCertificateException("mTLS client certificate required");
        }
        X509Certificate tlsClientCert = peerCerts[0];

        // 2. Fetch stored challenge for this client cert
        String certId = challengeService.computeCertId(tlsClientCert);
        Challenge challenge = challengeService.getChallengeByCertId(certId);
        if (challenge == null) {
            throw new ChallengeNotFoundException("No challenge found for this certificate or already used");
        }

        log.info("Challenge found for certificate ID: {}", certId);

        // 3. Parse provided signing certificate (mandatory now)
        X509Certificate signingCert = certificateUtilsService.parseCertificateFromAnyFormat(request.getSigningCertificate());
        X509Certificate signingRoot = certificateUtilsService.loadCertificate(appConfig.getSecurity().getSigningCaCertPath());
        // 4. Verify signing certificate chain against Signing Root CA
        boolean trusted = isCertificateTrustedAgainstAnchor(
                signingCert,
                signingRoot // path to your Signing Root CA
        );
        if (!trusted) {
            throw new CertNotTrustedException("Signing certificate is not issued by Signing Root CA");
        }

        log.info("Signing certificate trusted by Signing Root CA");

        // 5. Decode signature
        byte[] sigBytes;
        sigBytes = Base64.getDecoder().decode(request.getSignedData());


        // 6. Verify signature against challenge with signing cert pubkey
        boolean ok = verifySignature(challenge.getData(), sigBytes, signingCert);
        if (!ok) {
            throw new SignatureNotValidException("Signature verification failed");
        }

        log.info("Signature successfully verified for certificate ID: {}", certId);

        // 7. Consume challenge
        challengeService.markConsumedByCertId(certId);
    }

    @Override
    public boolean verifySignature(byte[] data, byte[] signature, X509Certificate cert) throws Exception {
        PublicKey publicKey = cert.getPublicKey();
        String pubAlg = publicKey.getAlgorithm(); // e.g. "RSA", "EC", "DSA"

        String sigAlg = switch (pubAlg) {
            case "RSA" -> "SHA256withRSA";
            case "EC" -> "SHA256withECDSA";
            case "DSA" -> "SHA256withDSA";
            default -> throw new IllegalArgumentException("Unsupported public key algorithm: " + pubAlg);
        };

        Signature sig = Signature.getInstance(sigAlg);
        sig.initVerify(publicKey);
        sig.update(data);

        return sig.verify(signature);
    }

    @Override
    public boolean isCertificateTrustedAgainstAnchor(X509Certificate cert, X509Certificate rootCa) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            CertPath cp = cf.generateCertPath(Collections.singletonList(cert));

            TrustAnchor anchor = new TrustAnchor(rootCa, null);
            PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
            params.setRevocationEnabled(false);

            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            validator.validate(cp, params);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
