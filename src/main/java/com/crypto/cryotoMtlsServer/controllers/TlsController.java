package com.crypto.cryotoMtlsServer.controllers;

import com.crypto.cryotoMtlsServer.model.dtos.CertificateRequest;
import com.crypto.cryotoMtlsServer.model.dtos.CertificateRespond;
import com.crypto.cryotoMtlsServer.services.interfaces.ICertificateService;
import com.crypto.cryotoMtlsServer.services.interfaces.ICertificateUtilsService;
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
public class TlsController {

    private final ICertificateUtilsService certificateUtilsService;
    private final ICertificateService certificateService;

    @GetMapping("/tls-establish")
    public ResponseEntity<Map<String, String>> tlsEstablish() {
        Map<String, String> response = new HashMap<>();
        response.put("status", "success");
        response.put("message", "TLS handshake completed successfully.");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/import-cas")
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
    public ResponseEntity<CertificateRespond> importCertificates(@Valid @RequestBody CertificateRequest certificateRequest) {

        try {
            if (certificateRequest.getMtls_csr() == null || certificateRequest.getSigning_csr() == null) {
                return ResponseEntity.badRequest().body(
                        new CertificateRespond( "error", "CSRs for mTLS and signing are required",null,null, null, null)
                );
            }

            X509Certificate mtlsCert = certificateService.signCSR(
                    certificateRequest.getMtls_csr(),
                    "src/main/resources/certs/mtls_root_ca.cert.pem",
                    "src/main/resources/private/mtls_root_ca.key.pem"
            );

            X509Certificate signingCert = certificateService.signCSR(
                    certificateRequest.getSigning_csr(),
                    "src/main/resources/certs/signing_root_ca.cert.pem",
                    "src/main/resources/private/signing_root_ca.key.pem"
            );

            String mtlsRootCa = certificateUtilsService.toBase64(certificateUtilsService.loadCertificate("src/main/resources/certs/mtls_root_ca.cert.pem"));
            String signingRootCa = certificateUtilsService.toBase64(certificateUtilsService.loadCertificate("src/main/resources/certs/signing_root_ca.cert.pem"));

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
