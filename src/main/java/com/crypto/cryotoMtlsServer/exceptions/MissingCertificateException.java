package com.crypto.cryotoMtlsServer.exceptions;

public class MissingCertificateException extends RuntimeException {

    public MissingCertificateException(String message) {
        super(message);
    }
}
