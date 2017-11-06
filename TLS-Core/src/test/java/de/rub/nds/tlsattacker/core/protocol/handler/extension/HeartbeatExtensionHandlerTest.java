/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.core.protocol.message.extension.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.HeartbeatExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.HeartbeatExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.HeartbeatExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class HeartbeatExtensionHandlerTest {

    private HeartbeatExtensionHandler handler;

    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new HeartbeatExtensionHandler(context);
    }

    /**
     * Test of adjustTLSContext method, of class HeartbeatExtensionHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        HeartbeatExtensionMessage msg = new HeartbeatExtensionMessage();
        msg.setHeartbeatMode(new byte[] { 1 });
        handler.adjustTLSContext(msg);
        assertTrue(context.getHeartbeatMode() == HeartbeatMode.PEER_ALLOWED_TO_SEND);
    }

    @Test
    public void testAdjustUnspecifiedMode() {
        HeartbeatExtensionMessage msg = new HeartbeatExtensionMessage();
        msg.setHeartbeatMode(new byte[] { (byte) 0xFF });
        handler.adjustTLSContext(msg);
        assertNull(context.getHeartbeatMode());
    }

    /**
     * Test of getParser method, of class HeartbeatExtensionHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[] { 0, 1, 2, }, 0) instanceof HeartbeatExtensionParser);
    }

    /**
     * Test of getPreparator method, of class HeartbeatExtensionHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new HeartbeatExtensionMessage()) instanceof HeartbeatExtensionPreparator);
    }

    /**
     * Test of getSerializer method, of class HeartbeatExtensionHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new HeartbeatExtensionMessage()) instanceof HeartbeatExtensionSerializer);
    }

}
