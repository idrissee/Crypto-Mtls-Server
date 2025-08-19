package com.crypto.cryotoMtlsServer.model.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CertificateRespond {

    private String status;
    private String message;
    private String mtls_cert;
    private List<String> mtls_chain;
    private String signing_cert;
    private List<String> signing_chain;
}
