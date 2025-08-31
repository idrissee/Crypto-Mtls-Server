package com.crypto.cryotoMtlsServer.services.interfaces;

import com.crypto.cryotoMtlsServer.model.domain.Challenge;

import java.security.cert.X509Certificate;

public interface IChallengeService {
    String createChallenge(X509Certificate clientCert);


    Challenge getChallengeByCertId(String certId);

    void markConsumedByCertId(String certId);

    String computeCertId(X509Certificate cert);
}
