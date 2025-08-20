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
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

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
    @Operation(summary = "Establish TLS connection", description = "Returns success if TLS handshake was established.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "TLS handshake completed successfully"),
            @ApiResponse(responseCode = "500", description = "Internal server error occurred while processing the request")})
    public ResponseEntity<Map<String, String>> tlsEstablish() {
        Map<String, String> response = new HashMap<>();
        response.put("status", "success");
        response.put("message", "TLS handshake completed successfully.");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/import-cas")
    @Operation(summary = "import CA's certificates", description = "This endpoint is used to import CA certificates.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Successfully imported CA certificates"),
            @ApiResponse(responseCode = "500", description = "Internal server error occurred while processing the request")})
    public ResponseEntity<Map<String, Object>> importCas() {
        Map<String, Object> response = new HashMap<>();
        try {
            String mtlsRootCa = certificateUtilsService.loadCertAsBase64("certs/mtls_root_ca.cert.pem");
            String signingRootCa = certificateUtilsService.loadCertAsBase64("certs/signing_root_ca.cert.pem");

            response.put("status", "success");
            response.put("mtls_rootca", mtlsRootCa);
            response.put("signing_rootca", signingRootCa);
            log.info("Root CA certificates imported successfully.");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
    }

    @PostMapping("/import-certificates")
    @Operation(summary ="Import certificates", description = " This endpoint is used to import mTLS and signing certificates and their chain by signing CSRs.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Certificates imported successfully"),
            @ApiResponse(responseCode = "500", description = "Internal server error occurred while processing the request"),
            @ApiResponse(responseCode = "400", description = "Bad request, invalid input or parameters")
    } )
    public ResponseEntity<CertificateRespond> importCertificates(@Valid @RequestBody CertificateRequest certificateRequest) {

        try {
            if (certificateRequest.getMtls_csr() == null || certificateRequest.getSigning_csr() == null) {
                return ResponseEntity.badRequest().body(
                        new CertificateRespond( "error", "CSRs for mTLS and signing are required",null,null, null, null)
                );
            }

            X509Certificate mtlsCert = certificateService.signCSR(
                    certificateRequest.getMtls_csr(),
                    appConfig.getSecurity().getMtlsCaCertPath(),
                    appConfig.getSecurity().getMtlsCaKeyPath()

            );

            X509Certificate signingCert = certificateService.signCSR(
                    certificateRequest.getSigning_csr(),
                    appConfig.getSecurity().getSigningCaCertPath(),
                    appConfig.getSecurity().getSigningCaKeyPath()
            );

            String mtlsRootCa = certificateUtilsService.loadCertAsBase64(appConfig.getSecurity().getMtlsCaCertPath());
            String signingRootCa = certificateUtilsService.loadCertAsBase64(appConfig.getSecurity().getSigningCaCertPath());

            return ResponseEntity.ok()
                   .body(
                   new CertificateRespond(
                    "success",
                    "Certificates imported successfully",
                    certificateUtilsService.toBase64(mtlsCert),
                           List.of(certificateUtilsService.toBase64(mtlsCert), mtlsRootCa),
                    certificateUtilsService.toBase64(signingCert),
                            List.of(certificateUtilsService.toBase64(signingCert), signingRootCa)
                   )
                   );

        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                   new CertificateRespond( "error", e.getMessage(),null,null, null, null)
            );
        }

    }

}
