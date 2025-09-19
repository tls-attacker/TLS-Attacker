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
import static org.junit.jupiter.api.Assertions.assertNotSame;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
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
        byte[] seed = DataConverter.concatenate(serverRdm, clientRdm);
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

    @Test
    public void testGetSenderConstantReturnsDefensiveCopy() {
        // Test that getSenderConstant returns a defensive copy (not the same array instance)
        byte[] serverConstant1 = SSLUtils.getSenderConstant(ConnectionEndType.SERVER);
        byte[] serverConstant2 = SSLUtils.getSenderConstant(ConnectionEndType.SERVER);

        // Verify they have the same content
        assertArrayEquals(serverConstant1, serverConstant2);

        // Verify they are different instances (defensive copy)
        assertNotSame(serverConstant1, serverConstant2);

        // Test the same for CLIENT
        byte[] clientConstant1 = SSLUtils.getSenderConstant(ConnectionEndType.CLIENT);
        byte[] clientConstant2 = SSLUtils.getSenderConstant(ConnectionEndType.CLIENT);

        assertArrayEquals(clientConstant1, clientConstant2);
        assertNotSame(clientConstant1, clientConstant2);

        // Verify that modifying the returned array doesn't affect the original
        byte[] serverConstant3 = SSLUtils.getSenderConstant(ConnectionEndType.SERVER);
        byte originalValue = serverConstant3[0];
        serverConstant3[0] = (byte) (serverConstant3[0] + 1);

        byte[] serverConstant4 = SSLUtils.getSenderConstant(ConnectionEndType.SERVER);
        assertArrayEquals(serverConstant1, serverConstant4); // Should still be equal to original
    }
}
