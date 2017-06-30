/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KS.KSEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KS.KeySharePair;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.KeyShareExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.KeyShareExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.KeyShareExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.util.LinkedList;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class KeyShareExtensionHandlerTest {

    private TlsContext context;
    private KeyShareExtensionHandler handler;

    public KeyShareExtensionHandlerTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new KeyShareExtensionHandler(context);
    }

    /**
     * Test of adjustTLSContext method, of class KeyShareExtensionHandler.
     * Group: ECDH_X25519
     */
    @Test
    public void testAdjustTLSContext() {
        context.getConfig().setConnectionEnd(ConnectionEnd.CLIENT);
        context.setTalkingConnectionEnd(ConnectionEnd.SERVER);
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        KeyShareExtensionMessage msg = new KeyShareExtensionMessage();
        List<KeySharePair> pairList = new LinkedList<>();
        KeySharePair pair = new KeySharePair();
        pair.setKeyShare(ArrayConverter
                .hexStringToByteArray("9c1b0a7421919a73cb57b3a0ad9d6805861a9c47e11df8639d25323b79ce201c"));
        pair.setKeyShareType(NamedCurve.ECDH_X25519.getValue());
        pairList.add(pair);
        msg.setKeyShareList(pairList);
        handler.adjustTLSContext(msg);
        assertNotNull(context.getServerKSEntry());
        KSEntry entry = context.getServerKSEntry();
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("9c1b0a7421919a73cb57b3a0ad9d6805861a9c47e11df8639d25323b79ce201c"),
                entry.getSerializedPublicKey());
        assertTrue(entry.getGroup() == NamedCurve.ECDH_X25519);
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("EA2F968FD0A381E4B041E6D8DDBF6DA93DE4CEAC862693D3026323E780DB9FC3"),
                context.getHandshakeSecret());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("C56CAE0B1A64467A0E3A3337F8636965787C9A741B0DAB63E503076051BCA15C"),
                context.getClientHandshakeTrafficSecret());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("DBF731F5EE037C4494F24701FF074AD4048451C0E2803BC686AF1F2D18E861F5"),
                context.getServerHandshakeTrafficSecret());
    }

    /**
     * Test of getParser method, of class KeyShareExtensionHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[] { 0, 2, 3, }, 0) instanceof KeyShareExtensionParser);
    }

    /**
     * Test of getPreparator method, of class KeyShareExtensionHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new KeyShareExtensionMessage()) instanceof KeyShareExtensionPreparator);
    }

    /**
     * Test of getSerializer method, of class KeyShareExtensionHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new KeyShareExtensionMessage()) instanceof KeyShareExtensionSerializer);
    }
}
