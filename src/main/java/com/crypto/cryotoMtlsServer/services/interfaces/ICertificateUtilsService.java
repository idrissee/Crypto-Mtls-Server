package com.crypto.cryotoMtlsServer.services.interfaces;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public interface ICertificateUtilsService {
    String loadCertAsBase64(String certPath) throws IOException;

    PrivateKey loadPrivateKey(String path) throws Exception;

    X509Certificate loadCertificate(String path) throws Exception;

    String toBase64(X509Certificate cert) throws Exception;
}
