/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.HeartbeatExtensionMessage;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class HeartbeatExtensionHandlerTest {

    private HeartbeatExtensionHandler handler;

    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new HeartbeatExtensionHandler(context);
    }

    /**
     * Test of adjustContext method, of class HeartbeatExtensionHandler.
     */
    @Test
    public void testadjustContext() {
        HeartbeatExtensionMessage msg = new HeartbeatExtensionMessage();
        msg.setHeartbeatMode(new byte[] { 1 });
        handler.adjustContext(msg);
        assertTrue(context.getHeartbeatMode() == HeartbeatMode.PEER_ALLOWED_TO_SEND);
    }

    @Test
    public void testAdjustUnspecifiedMode() {
        HeartbeatExtensionMessage msg = new HeartbeatExtensionMessage();
        msg.setHeartbeatMode(new byte[] { (byte) 0xFF });
        handler.adjustContext(msg);
        assertNull(context.getHeartbeatMode());
    }
}
