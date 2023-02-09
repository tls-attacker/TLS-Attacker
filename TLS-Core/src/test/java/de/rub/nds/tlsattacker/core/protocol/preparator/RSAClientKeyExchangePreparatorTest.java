/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
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
import java.io.ByteArrayInputStream;
import java.io.IOException;
import org.bouncycastle.crypto.tls.Certificate;
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
        // TODO
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
        context.setHighestClientProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setClientRandom(ArrayConverter.hexStringToByteArray("AABBCCDDEEFF"));
        context.setServerRandom(ArrayConverter.hexStringToByteArray("AABBCCDDEEFF"));
        // Test
        preparator.prepareHandshakeMessageContents();
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

    private Certificate parseCertificate(int lengthBytes, byte[] bytesToParse) {
        try {
            ByteArrayInputStream stream =
                    new ByteArrayInputStream(
                            ArrayConverter.concatenate(
                                    ArrayConverter.intToBytes(
                                            lengthBytes, HandshakeByteLength.CERTIFICATES_LENGTH),
                                    bytesToParse));
            return Certificate.parse(stream);
        } catch (IOException E) {
            return null;
        }
    }
}
