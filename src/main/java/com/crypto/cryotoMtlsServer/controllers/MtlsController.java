package com.crypto.cryotoMtlsServer.controllers;


import com.crypto.cryotoMtlsServer.exceptions.MissingCertificateException;
import com.crypto.cryotoMtlsServer.services.impl.CertificateUtilsService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.cert.X509Certificate;

@RestController
@RequiredArgsConstructor
@Slf4j
@Tag( name ="Mtls endpoints" , description = "endpoints for managing mtls operation")
public class MtlsController {

    private final CertificateUtilsService certificateUtilsService;

    @Operation(
            summary = "Access a protected endpoint",
            description = "This endpoint requires a valid client certificate signed by the mTLS Root CA."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Client authenticated successfully. Returns client certificate subject."),
            @ApiResponse(responseCode = "403", description = "Client authentication failed or invalid certificate."),
            @ApiResponse(responseCode = "500", description = "Internal server error.")
    })
    @SecurityRequirement(name = "mtls")
    @GetMapping("/protected")
    public ResponseEntity<String> protectedEndpoint(HttpServletRequest request) {

            X509Certificate[] certs = (X509Certificate[]) request.getAttribute("jakarta.servlet.request.X509Certificate");

            String subject = certificateUtilsService.checkCertificate(certs);

            return new ResponseEntity<>("Hello secure client: " + subject, HttpStatus.OK);
        }


}


