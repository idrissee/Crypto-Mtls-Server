package com.crypto.cryotoMtlsServer.controllers;

import com.crypto.cryotoMtlsServer.model.dtos.GetDataResponse;
import com.crypto.cryotoMtlsServer.model.dtos.PostDataRequest;
import com.crypto.cryotoMtlsServer.services.interfaces.ICertificateUtilsService;
import com.crypto.cryotoMtlsServer.services.interfaces.IChallengeService;
import com.crypto.cryotoMtlsServer.services.interfaces.ISignatureService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.security.cert.X509Certificate;



@RestController
@RequiredArgsConstructor
@Slf4j
@Tag( name ="Mtls endpoints" , description = "endpoints for managing mtls operation")
public class MtlsController {

    private final ICertificateUtilsService certificateUtilsService;
    private final IChallengeService challengeService;
    private final ISignatureService signatureService;

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

            log.info("Certificate validated successfully for subject: {}", subject);
            return new ResponseEntity<>("Hello secure client: " + subject, HttpStatus.OK);
        }


    @Operation(summary = "Get challenge data to sign (mTLS required)")
    @ApiResponses(value = {
            @ApiResponse( responseCode = "200" , description = "200 status success "),
            @ApiResponse(responseCode = "403", description = "Client authentication failed or invalid certificate."),
            @ApiResponse( responseCode = "500" , description = "Internal server error.")
    })
    @SecurityRequirement(name = "mtls")
    @GetMapping("/get-data")
    public ResponseEntity<GetDataResponse> getData(HttpServletRequest request) {
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute("jakarta.servlet.request.X509Certificate");

        certificateUtilsService.checkCertificate(certs);

        X509Certificate clientCert = certs[0];

        String based64Challenge = challengeService.createChallenge(clientCert);

        log.info("Challenge data generated and sent to client.");
        return new ResponseEntity<>(new GetDataResponse(based64Challenge),HttpStatus.OK);
    }



    @Operation(
            summary = "Verify challenge data using mTLS and digital signature",
            description = "This endpoint verifies the client certificate challenge response. It checks the presence of an mTLS certificate, retrieves the associated challenge, validates the provided signing certificate and signature, and consumes the challenge if verification succeeds."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Signature verified successfully"),
            @ApiResponse(responseCode = "400", description = "Bad request - malformed data, missing or invalid fields"),
            @ApiResponse(responseCode = "404", description = "Challenge not found or already used"),
            @ApiResponse(responseCode = "403", description = "Forbidden -  Client authentication failed or invalid certificate."),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @SecurityRequirement(name = "mtls")
    @PostMapping("/post-data")
    public ResponseEntity<String> postData(@Valid @RequestBody PostDataRequest request,
                                                     HttpServletRequest httpRequest) throws Exception {
        // 1. TLS client certificate required
        X509Certificate[] peerCerts = (X509Certificate[]) httpRequest.getAttribute("jakarta.servlet.request.X509Certificate");

        signatureService.verfiyChallengeData(peerCerts, request);

        log.info("Challenge data verified successfully.");
        return new ResponseEntity<>("Signature verified successfully" , HttpStatus.OK);
    }

}

