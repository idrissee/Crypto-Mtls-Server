package com.crypto.cryotoMtlsServer.controllers;

import com.crypto.cryotoMtlsServer.configuration.AppConfig;
import com.crypto.cryotoMtlsServer.model.dtos.CertificateRequest;
import com.crypto.cryotoMtlsServer.model.dtos.CertificateRespond;
import com.crypto.cryotoMtlsServer.services.interfaces.ICertificateService;
import com.crypto.cryotoMtlsServer.services.interfaces.ICertificateUtilsService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@Slf4j
@RequiredArgsConstructor
@Tag(name = "TLS end points", description = "Endpoints for managing TLS operations")
public class TlsController {

    private final AppConfig appConfig;
    private final ICertificateUtilsService certificateUtilsService;
    private final ICertificateService certificateService;

    @GetMapping("/tls-establish")
    @Operation(
            summary = "Establish TLS connection"
            , description = "Returns success if TLS handshake was established.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "TLS handshake completed successfully"),
            @ApiResponse(responseCode = "500", description = "Internal server error occurred while processing the request")
    })
    public ResponseEntity<Map<String, String>> tlsEstablish() {

        Map<String, String> response = new HashMap<>();
        response.put("status", "success");
        response.put("message", "TLS handshake completed successfully.");

        return new ResponseEntity<>(response , HttpStatus.OK);
    }

    @GetMapping("/import-cas")
    @Operation(
            summary = "import CA's certificates",
            description = "This endpoint is used to import CA certificates.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Successfully imported CA certificates"),
            @ApiResponse(responseCode = "500", description = "Internal server error occurred while processing the request")
    })
    public ResponseEntity<Map<String, Object>> importCas() throws IOException {
        Map<String, Object> response = new HashMap<>();

            String mtlsRootCa = certificateUtilsService.loadCertAsBase64(appConfig.getSecurity().getMtlsCaCertPath());
            String signingRootCa = certificateUtilsService.loadCertAsBase64(appConfig.getSecurity().getSigningCaCertPath());

            response.put("status", "success");
            response.put("mtls_rootca", mtlsRootCa);
            response.put("signing_rootca", signingRootCa);

            log.info("Root CA certificates imported successfully.");
            return ResponseEntity.ok(response);

    }

    @PostMapping("/import-certificates")
    @Operation(summary ="Import certificates", description = " This endpoint is used to import mTLS and signing certificates and their chain by signing CSRs.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Certificates imported successfully"),
            @ApiResponse(responseCode = "500", description = "Internal server error occurred while processing the request"),
    } )
    public ResponseEntity<CertificateRespond> importCertificates(@Valid @RequestBody CertificateRequest certificateRequest) throws Exception {


            X509Certificate mtlsCert = certificateService.signCSR("mtls"
                    , certificateRequest.getMtls_csr()
                    , appConfig.getSecurity().getMtlsCaCertPath()
                    , appConfig.getSecurity().getMtlsCaKeyPath());

            X509Certificate signingCert = certificateService.signCSR("signing",
                    certificateRequest.getSigning_csr(),
                    appConfig.getSecurity().getSigningCaCertPath(),
                    appConfig.getSecurity().getSigningCaKeyPath()
            );

            String mtlsRootCa = certificateUtilsService.loadCertAsBase64(appConfig.getSecurity().getMtlsCaCertPath());
            String signingRootCa = certificateUtilsService.loadCertAsBase64(appConfig.getSecurity().getSigningCaCertPath());


            log.info("csr's signed and imported certificates successfully.");
            return new ResponseEntity<>(new CertificateRespond(
                    "success",
                    "Certificates imported successfully",
                    certificateUtilsService.toBase64(mtlsCert),
                    List.of(certificateUtilsService.toBase64(mtlsCert), mtlsRootCa),
                    certificateUtilsService.toBase64(signingCert),
                    List.of(certificateUtilsService.toBase64(signingCert), signingRootCa)
            ),HttpStatus.OK);

        }


    }

