/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.application;

import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import static org.junit.Assert.assertEquals;
import org.junit.Test;
import static org.junit.Assert.assertArrayEquals;

/**
 * 
 * @author Robert Merget
 */
public class ApplicationHandlerTest {
    /**
     * Test of parseMessageAction method, of class ApplicationHandler.
     */
    @Test
    public void testParseMessageAction() {
        ApplicationHandler handler = new ApplicationHandler(new TlsContext());
        handler.setProtocolMessage(new ApplicationMessage(new TlsConfig()));
        byte[] message = { 1, 2, 3, 4 };
        int pointer = handler.parseMessageAction(message, 0);
        assertEquals(message.length, pointer);
        assertArrayEquals(message, handler.getProtocolMessage().getData().getOriginalValue());

    }
}
