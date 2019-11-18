/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.KeyShareExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.KeyShareExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.KeyShareExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class KeyShareExtensionHandlerTest {

    private TlsContext context;
    private KeyShareExtensionHandler handler;

    public KeyShareExtensionHandlerTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new KeyShareExtensionHandler(context, ExtensionType.KEY_SHARE);
    }

    /**
     * Test of adjustTLSContext method, of class KeyShareExtensionHandler.
     * Group: ECDH_X25519
     */
    @Test
    public void testAdjustTLSContext() {
        context.setConnection(new OutboundConnection());
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        KeyShareExtensionMessage msg = new KeyShareExtensionMessage();
        List<KeyShareEntry> pairList = new LinkedList<>();
        KeyShareEntry pair = new KeyShareEntry(NamedGroup.ECDH_X25519,
                new BigInteger(ArrayConverter
                        .hexStringToByteArray("03BD8BCA70C19F657E897E366DBE21A466E4924AF6082DBDF573827BCDDE5DEF")));
        pair.setPublicKey(ArrayConverter
                .hexStringToByteArray("9c1b0a7421919a73cb57b3a0ad9d6805861a9c47e11df8639d25323b79ce201c"));
        pair.setGroup(NamedGroup.ECDH_X25519.getValue());
        pairList.add(pair);
        msg.setKeyShareList(pairList);
        handler.adjustTLSContext(msg);
        assertNotNull(context.getServerKeyShareStoreEntry());
        KeyShareStoreEntry entry = context.getServerKeyShareStoreEntry();
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("9c1b0a7421919a73cb57b3a0ad9d6805861a9c47e11df8639d25323b79ce201c"),
                entry.getPublicKey());
        assertTrue(entry.getGroup() == NamedGroup.ECDH_X25519);
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
