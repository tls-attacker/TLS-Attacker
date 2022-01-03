/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.certificate;

import de.rub.nds.tlsattacker.core.crypto.keys.CustomECPrivateKey;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomEcPublicKey;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import org.junit.Test;
import static org.junit.Assert.assertThat;
import static org.hamcrest.CoreMatchers.containsString;

public class PemUtilTest {

    private static final String SECRET =
        "45920025678221661724778903394380424235512150060610104911582497586860611281771";

    /**
     * Test of writePrivateKey method, of class PemUtil.
     */
    @Test
    public void testWritePrivateKey() {
        BigInteger secret = new BigInteger(SECRET);
        CustomECPrivateKey key = new CustomECPrivateKey(secret, NamedGroup.SECP256R1);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PemUtil.writePrivateKey(key.getEncoded(), baos);
        String result = new String(baos.toByteArray());
        assertThat(result, containsString("-----BEGIN PRIVATE KEY-----"));
        assertThat(result, containsString("MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBlhdBA2pVVpBpVqfWQ"));
        assertThat(result, containsString("-----END PRIVATE KEY-----"));
    }

    @Test
    public void testWritePublicKey() {
        CustomEcPublicKey key = new CustomEcPublicKey(BigInteger.ONE, BigInteger.TEN, NamedGroup.SECP256R1);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PemUtil.writePublicKey(key, baos);
        String result = new String(baos.toByteArray());
        assertThat(result, containsString("-----BEGIN PUBLIC KEY-----"));
        assertThat(result, containsString("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        assertThat(result, containsString("-----END PUBLIC KEY-----"));
    }
}
