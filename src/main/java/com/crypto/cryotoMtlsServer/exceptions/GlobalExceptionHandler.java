package com.crypto.cryotoMtlsServer.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(value = { Exception.class})
    public ResponseEntity<?> handleException(Exception ex) {

        return new ResponseEntity<>(ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(value = { MissingCertificateException.class })
    public ResponseEntity<?> handleMissingCertificateException(MissingCertificateException ex) {

        return new ResponseEntity<>(ex.getMessage(), HttpStatus.FORBIDDEN);
    }

}
