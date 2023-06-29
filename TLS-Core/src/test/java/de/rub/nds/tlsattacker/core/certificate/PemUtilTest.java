/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate;

import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomECPrivateKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomEcPublicKey;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

public class PemUtilTest {

    private static final String SECRET =
            "45920025678221661724778903394380424235512150060610104911582497586860611281771";

    /** Test of writePrivateKey method, of class PemUtil. */
    @Test
    public void testWritePrivateKey() {
        BigInteger secret = new BigInteger(SECRET);
        CustomECPrivateKey key = new CustomECPrivateKey(secret, NamedGroup.SECP256R1);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PemUtil.writePrivateKey(key.getEncoded(), baos);
        String result = baos.toString();
        assertTrue(result.contains("-----BEGIN PRIVATE KEY-----"));
        assertTrue(
                result.contains(
                        "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBlhdBA2pVVpBpVqfWQ"));
        assertTrue(result.contains("-----END PRIVATE KEY-----"));
    }

    @Test
    public void testWritePublicKey() {
        CustomEcPublicKey key =
                new CustomEcPublicKey(BigInteger.ONE, BigInteger.TEN, NamedGroup.SECP256R1);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PemUtil.writePublicKey(key, baos);
        String result = baos.toString();
        assertTrue(result.contains("-----BEGIN PUBLIC KEY-----"));
        assertTrue(
                result.contains(
                        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        assertTrue(result.contains("-----END PUBLIC KEY-----"));
    }
}
