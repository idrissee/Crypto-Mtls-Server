package com.crypto.cryotoMtlsServer.exceptions;

public class CertNotTrustedException extends RuntimeException {
    public CertNotTrustedException(String message) {
        super(message);
    }
}
