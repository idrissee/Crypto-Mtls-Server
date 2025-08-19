package com.crypto.cryotoMtlsServer.configuration;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Configuration;

import java.security.Security;

@Configuration
@Slf4j
public class BouncyCastleConfig {


    @PostConstruct
    public void registerBouncyCstle(){
        if(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)== null){
            Security.addProvider(new BouncyCastleProvider());
            log.info("BouncyCastle provider registered.");
        }else {
            log.info("BouncyCastle provider already registered.");
        }
    }
}
