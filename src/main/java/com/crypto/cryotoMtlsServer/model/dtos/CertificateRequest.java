package com.crypto.cryotoMtlsServer.model.dtos;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CertificateRequest {
    @NotNull
    private String mtls_csr;
    @NotNull
    private String signing_csr;
}
