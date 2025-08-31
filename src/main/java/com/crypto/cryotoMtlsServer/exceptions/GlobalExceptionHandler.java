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

    @ExceptionHandler(value = { ChallengeNotFoundException.class })
        public ResponseEntity<?> handleChallengeNotFoundException(ChallengeNotFoundException ex) {

        return new ResponseEntity<>(ex.getMessage(), HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(value = { CertNotTrustedException.class })
    public ResponseEntity<?> handleCertNotTrustedException(CertNotTrustedException ex) {

        return new ResponseEntity<>(ex.getMessage(), HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(value = { SignatureNotValidException.class })
    public ResponseEntity<?> handleSignatureNotValidException(SignatureNotValidException ex) {

        return new ResponseEntity<>(ex.getMessage(), HttpStatus.BAD_REQUEST);
    }


}
