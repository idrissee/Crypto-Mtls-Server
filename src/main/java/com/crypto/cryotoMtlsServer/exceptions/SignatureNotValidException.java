package com.crypto.cryotoMtlsServer.exceptions;

public class SignatureNotValidException extends RuntimeException {
    public SignatureNotValidException(String message) {
        super(message);
    }
}
