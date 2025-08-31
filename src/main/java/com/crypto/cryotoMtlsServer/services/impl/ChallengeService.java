package com.crypto.cryotoMtlsServer.services.impl;

import com.crypto.cryotoMtlsServer.configuration.AppConfig;
import com.crypto.cryotoMtlsServer.model.domain.Challenge;
import com.crypto.cryotoMtlsServer.services.interfaces.IChallengeService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Slf4j
@RequiredArgsConstructor
public class ChallengeService implements IChallengeService {

    private final Map<String, Challenge> store = new ConcurrentHashMap<>();
    private final SecureRandom secureRandom = new SecureRandom();
    private final AppConfig appConfig;


    @Override
    public String createChallenge(X509Certificate clientCert) {
        byte[] data = new byte[appConfig.getSecurity().getChallengeLenght()];
        secureRandom.nextBytes(data);
        String certId = computeCertId(clientCert);
        String subject = clientCert.getSubjectX500Principal().getName();
        Challenge ch = new Challenge(certId, data, subject);
        store.put(certId, ch);

        log.info("[CREATE] Challenge issued for certId= {} subject= {} length= {}B",
                certId, subject, data.length);
        return Base64.getEncoder().encodeToString(ch.getData());
    }

    @Override
    public Challenge getChallengeByCertId(String certId) {
        return store.get(certId);
    }

    @Override
    public void markConsumedByCertId(String certId) {
        Challenge ch = store.get(certId);
        if (ch != null) {
            ch.markUsed();
            store.remove(certId);
            log.info("[CONSUME] Challenge consumed and removed for certId={}", certId);
        }else {
            log.warn("[CONSUME] Attempt to consume missing challenge for certId={}", certId);
        }
    }

    @Override
    public String computeCertId(X509Certificate cert) {
        // Use issuer DN + serial to uniquely identify the certificate instance
        String issuerCN = new X500Name(cert.getIssuerX500Principal().getName())
                .getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();
        String id =  issuerCN + "|" + cert.getSerialNumber().toString();
        log.debug("[COMPUTE] Computed certId={} from issuer={} serial={}", id, issuerCN, cert.getSerialNumber());
        return id;
    }

}
