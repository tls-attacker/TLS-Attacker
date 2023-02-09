/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class PemUtilTest {

    private static final String SECRET =
            "45920025678221661724778903394380424235512150060610104911582497586860611281771";

    /** Test of writePrivateKey method, of class PemUtil. */
    @Test
    public void testWritePrivateKey() {
        BigInteger secret = new BigInteger(SECRET);
        PrivateKey key = Mockito.mock(PrivateKey.class);
        Mockito.when(key.getEncoded()).thenReturn(new byte[] {1, 2, 3});
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PemUtil.writePrivateKey(key.getEncoded(), baos);
        String result = baos.toString();
        assertTrue(result.contains("-----BEGIN PRIVATE KEY-----"));
        assertTrue(result.contains("]6"));
        assertTrue(result.contains("-----END PRIVATE KEY-----"));
    }

    @Test
    public void testWritePublicKey() {
        PublicKey key = Mockito.mock(PublicKey.class);
        Mockito.when(key.getEncoded()).thenReturn(new byte[] {1, 2, 3});
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PemUtil.writePublicKey(key, baos);
        String result = baos.toString();
        assertTrue(result.contains("-----BEGIN PUBLIC KEY-----"));
        assertTrue(result.contains("]6"));
        assertTrue(result.contains("-----END PUBLIC KEY-----"));
    }
}
