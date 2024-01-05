/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

public class SSLUtilsTest {

    @ParameterizedTest
    @EnumSource(
            value = MacAlgorithm.class,
            names = {"SSLMAC_MD5", "SSLMAC_SHA1"})
    public void testSslMac(MacAlgorithm providedMacAlgorithm)
            throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] input = {1, 2, 3};
        byte[] masterSecret = {0, 1};
        byte[] clientRdm = {1};
        byte[] serverRdm = {0};
        byte[] seed = ArrayConverter.concatenate(serverRdm, clientRdm);
        int secretSetSize = 64;
        Mac digest = Mac.getInstance(providedMacAlgorithm.getJavaName());
        byte[] keyBlock = SSLUtils.calculateKeyBlockSSL3(masterSecret, seed, secretSetSize);
        byte[] macSecret = Arrays.copyOfRange(keyBlock, 0, digest.getMacLength());
        digest.init(new SecretKeySpec(macSecret, providedMacAlgorithm.getJavaName()));
        digest.update(input);
        byte[] jceResult = digest.doFinal();
        byte[] utilsResult = SSLUtils.calculateSSLMac(input, macSecret, providedMacAlgorithm);
        assertArrayEquals(jceResult, utilsResult);
    }
}
