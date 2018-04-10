/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Assert;
import org.junit.Test;

public class SSLUtilsTest {

    @Test
    public void testSSLMac() throws NoSuchAlgorithmException, InvalidKeyException {
        for (MacAlgorithm macAlgo : new MacAlgorithm[] { MacAlgorithm.SSLMAC_MD5, MacAlgorithm.SSLMAC_SHA1 }) {
            byte[] input = { 1, 2, 3 };
            byte[] masterSecret = { 0, 1 };
            byte[] clientRdm = { 1 };
            byte[] serverRdm = { 0 };
            byte[] seed = ArrayConverter.concatenate(serverRdm, clientRdm);
            int secretSetSize = 64;
            Mac digest = Mac.getInstance(macAlgo.getJavaName());
            byte[] keyBlock = SSLUtils.calculateKeyBlockSSL3(masterSecret, seed, secretSetSize);
            byte[] macSecret = Arrays.copyOfRange(keyBlock, 0, digest.getMacLength());
            digest.init(new SecretKeySpec(macSecret, macAlgo.getJavaName()));
            digest.update(input);
            byte[] jceResult = digest.doFinal();
            byte[] utilsResult = SSLUtils.calculateSSLMac(input, macSecret, macAlgo);
            Assert.assertArrayEquals(jceResult, utilsResult);
        }
    }

}
