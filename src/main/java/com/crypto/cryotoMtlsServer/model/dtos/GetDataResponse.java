package com.crypto.cryotoMtlsServer.model.dtos;


import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Schema(description = "Response for GET /get-data")
public class GetDataResponse {

    @Schema(description = "Base64 of random challenge bytes", example = "3q2+7w==")
    private String data;

}
