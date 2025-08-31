package com.crypto.cryotoMtlsServer.model.dtos;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class PostDataRequest {

    @NotBlank
    private String signedData; // base64 signature

    @NotBlank
    private String signingCertificate;
}
