/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.preparator.RSAClientKeyExchangePreparator;
import org.junit.Before;
import org.junit.Test;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.modifiablevariable.util.ArrayConverter;

import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class RSAClientKeyExchangePreparatorTest {

    private TlsContext context;
    private RSAClientKeyExchangePreparator preparator;
    private RSAClientKeyExchangeMessage message;

    public RSAClientKeyExchangePreparatorTest() {

    }

    @Before
    public void setUp() {
        context = new TlsContext();
        message = new RSAClientKeyExchangeMessage();
        preparator = new RSAClientKeyExchangePreparator(context, message);
    }

    /**
     * Test of prepareHandshakeMessageContents method, of class
     * RSAClientKeyExchangePreparator.
     */
    @Test
    public void testPrepare() {
        // TODO
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setClientRandom(ArrayConverter.hexStringToByteArray("AABBCCDDEEFF"));
        context.setServerRandom(ArrayConverter.hexStringToByteArray("AABBCCDDEEFF"));
        // Test
        preparator.prepareHandshakeMessageContents();
        assertArrayEquals(
                ArrayConverter.concatenate(ArrayConverter.hexStringToByteArray("AABBCCDDEEFF"),
                        ArrayConverter.hexStringToByteArray("AABBCCDDEEFF")), message.getComputations()
                        .getClientRandom().getValue());
        assertNotNull(message.getComputations().getPremasterSecret().getValue());
        assertEquals(HandshakeByteLength.PREMASTER_SECRET,
                message.getComputations().getPremasterSecret().getValue().length);
        assertEquals(ProtocolVersion.TLS12.getMajor(), message.getComputations().getPremasterSecret().getValue()[0]);
        assertEquals(ProtocolVersion.TLS12.getMinor(), message.getComputations().getPremasterSecret().getValue()[1]);
        assertNotNull(message.getComputations().getPlainPaddedPremasterSecret().getValue());
        // Check correct pkcs1 format
        assertEquals((byte) 0x00, message.getComputations().getPlainPaddedPremasterSecret().getValue()[0]);
        assertEquals((byte) 0x02, message.getComputations().getPlainPaddedPremasterSecret().getValue()[1]);
        assertEquals((byte) 0x00, message.getComputations().getPlainPaddedPremasterSecret().getValue()[message
                .getComputations().getPadding().getValue().length + 2]);
        assertNotNull(message.getComputations().getMasterSecret().getValue());
        assertEquals(HandshakeByteLength.MASTER_SECRET, message.getComputations().getMasterSecret().getValue().length);
        assertNotNull(message.getSerializedPublicKeyLength().getValue());
        assertNotNull(message.getSerializedPublicKey());
    }

}
