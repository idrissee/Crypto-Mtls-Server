package com.crypto.cryotoMtlsServer.services.interfaces;

import java.security.cert.X509Certificate;

public interface ICertificateService {

    X509Certificate signCSR(String csrBase64, String caCertPath, String caKeyPath) throws Exception;
}
