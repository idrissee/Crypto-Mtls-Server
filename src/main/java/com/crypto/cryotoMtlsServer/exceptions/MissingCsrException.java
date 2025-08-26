package com.crypto.cryotoMtlsServer.exceptions;

public class MissingCsrException extends RuntimeException {

    public MissingCsrException(String message) {
        super(message);
    }
}
