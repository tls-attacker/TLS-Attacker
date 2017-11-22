/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.PaddingExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.PaddingExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PaddingExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class PaddingExtensionHandlerTest {

    private final byte[] extensionPayload = new byte[] { 0, 0, 0, 0, 0, 0 };
    private TlsContext context;
    private PaddingExtensionHandler handler;

    /**
     * Some initial set up.
     */

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new PaddingExtensionHandler(context);
    }

    /**
     * Test of adjustTLSContext method, of class PaddingExtensionHandler.
     */

    @Test
    public void testAdjustTLSContext() {
        PaddingExtensionMessage msg = new PaddingExtensionMessage();
        msg.setPaddingBytes(extensionPayload);
        handler.adjustTLSContext(msg);
        assertArrayEquals(context.getPaddingExtensionBytes(), extensionPayload);
    }

    /**
     * Test of getParser method, of class PaddingExtensionHandler.
     */

    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[0], 0) instanceof PaddingExtensionParser);
    }

    /**
     * Test of getPreparator method, of class PaddingExtensionHandler.
     */

    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new PaddingExtensionMessage()) instanceof PaddingExtensionPreparator);
    }

    /**
     * Test of getSerializer method, of class PaddingExtensionHandler.
     */

    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new PaddingExtensionMessage()) instanceof PaddingExtensionSerializer);
    }

}
