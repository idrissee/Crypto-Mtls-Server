package com.crypto.cryotoMtlsServer.model.domain;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.concurrent.atomic.AtomicBoolean;

@Data
@AllArgsConstructor
public class Challenge {

    private final String certId;
    private final byte[] data;
    private final String clientSubject; // DN string
    private final AtomicBoolean used = new AtomicBoolean(false);

    public void markUsed() {
        used.compareAndSet(false, true);
    }

}
