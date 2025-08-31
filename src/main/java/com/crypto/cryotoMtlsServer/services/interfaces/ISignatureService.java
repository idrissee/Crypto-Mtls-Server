package com.crypto.cryotoMtlsServer.services.interfaces;

import com.crypto.cryotoMtlsServer.model.dtos.PostDataRequest;

import java.security.cert.X509Certificate;

public interface ISignatureService {
    void verfiyChallengeData(X509Certificate[] peerCerts, PostDataRequest request) throws Exception;

    boolean verifySignature(byte[] data, byte[] signature, X509Certificate cert) throws Exception;

    boolean isCertificateTrustedAgainstAnchor(X509Certificate cert, X509Certificate rootCa);
}
