/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

public class RSAClientKeyExchangePreparatorTest
        extends AbstractProtocolMessagePreparatorTest<
                RSAClientKeyExchangeMessage,
                RSAClientKeyExchangePreparator<RSAClientKeyExchangeMessage>> {

    public RSAClientKeyExchangePreparatorTest() {
        super(RSAClientKeyExchangeMessage::new, RSAClientKeyExchangePreparator::new);
    }

    /** Test of prepareHandshakeMessageContents method, of class RSAClientKeyExchangePreparator. */
    @Test
    @Override
    public void testPrepare() {
        setParameters();
        // Test
        preparator.prepareHandshakeMessageContents();
        checkMessageContents();
    }

    private void setParameters() {
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
        context.setHighestClientProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setClientRandom(ArrayConverter.hexStringToByteArray("AABBCCDDEEFF"));
        context.setServerRandom(ArrayConverter.hexStringToByteArray("AABBCCDDEEFF"));
    }

    private void checkMessageContents() {
        assertArrayEquals(
                ArrayConverter.concatenate(
                        ArrayConverter.hexStringToByteArray("AABBCCDDEEFF"),
                        ArrayConverter.hexStringToByteArray("AABBCCDDEEFF")),
                message.getComputations().getClientServerRandom().getValue());
        assertNotNull(message.getComputations().getPremasterSecret().getValue());
        assertEquals(
                HandshakeByteLength.PREMASTER_SECRET,
                message.getComputations().getPremasterSecret().getValue().length);
        assertEquals(
                ProtocolVersion.TLS12.getMajor(),
                message.getComputations().getPremasterSecret().getValue()[0]);
        assertEquals(
                ProtocolVersion.TLS12.getMinor(),
                message.getComputations().getPremasterSecret().getValue()[1]);
        assertNotNull(message.getComputations().getPlainPaddedPremasterSecret().getValue());
        // Check correct pkcs1 format
        assertEquals(
                (byte) 0x00,
                message.getComputations().getPlainPaddedPremasterSecret().getValue()[0]);
        assertEquals(
                (byte) 0x02,
                message.getComputations().getPlainPaddedPremasterSecret().getValue()[1]);
        assertEquals(
                (byte) 0x00,
                message.getComputations()
                        .getPlainPaddedPremasterSecret()
                        .getValue()[message.getComputations().getPadding().getValue().length + 2]);
        assertNotNull(message.getPublicKeyLength().getValue());
        assertNotNull(message.getPublicKey());
    }

    @Test
    public void testEncryptWithOddModulus() {
        setParameters();
        BigInteger modulus2046bits =
                new BigInteger(
                        "3beb21d42ac899b13c7eeacee9f0f2d27f41beed0041ed834539de666650ccaedb63a2be928b1b80fef09fe0c19c7cfd9e2a07bb011923ccad761b0e22fe8a48c755d676c3a96545640af27a5a34ce9595c73df21f4ea362f91569f6a1ad16a8e04ae607232cb7e7aed913bb636d488e6152875ddbcdc6c62c171f9c57305fa570f3b9c5b18b8176bc6efaf727bfac486cc775d8100c49f1131f491040b5c2819f268521d5affd14012922934f573038364f16f54c98ef432bbf2956703a1ba8f9922e8fe3deee5d99a4aa629a0b29cb939d6c83f807bf90094d9257c44f0f50ebc8105f6bbb9bb51c611934dd1441c7f2917916c3c4056251898f764f7fd8c5",
                        16);
        context.getServerX509Context().setSubjectRsaModulus(modulus2046bits);
        context.getServerX509Context().setSubjectRsaPublicExponent(BigInteger.valueOf(65537));
        preparator.prepareHandshakeMessageContents();
        assertEquals(256, message.getPublicKey().getValue().length);
        checkMessageContents();
    }
}
