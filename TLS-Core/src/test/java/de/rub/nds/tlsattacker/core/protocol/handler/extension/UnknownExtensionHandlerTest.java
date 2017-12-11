/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.UnknownExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.UnknownExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.UnknownExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.UnknownExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class UnknownExtensionHandlerTest {

    private UnknownExtensionHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new UnknownExtensionHandler(context);
    }

    /**
     * Test of adjustTLSContext method, of class UnknownExtensionHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        UnknownExtensionMessage msg = new UnknownExtensionMessage();
        handler.adjustTLSContext(msg);
        // TODO Check that context does not change
    }

    /**
     * Test of getParser method, of class UnknownExtensionHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[] { 0, 1, 2, 3, 4 }, 0) instanceof UnknownExtensionParser);
    }

    /**
     * Test of getPreparator method, of class UnknownExtensionHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new UnknownExtensionMessage()) instanceof UnknownExtensionPreparator);
    }

    /**
     * Test of getSerializer method, of class UnknownExtensionHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new UnknownExtensionMessage()) instanceof UnknownExtensionSerializer);
    }

}
