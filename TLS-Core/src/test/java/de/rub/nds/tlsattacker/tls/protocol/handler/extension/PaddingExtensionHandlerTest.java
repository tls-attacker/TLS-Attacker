/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler.extension;

import de.rub.nds.tlsattacker.tls.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.PaddingExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.PaddingExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.PaddingExtensionSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class PaddingExtensionHandlerTest {

    private PaddingExtensionHandler handler;

    private TlsContext context;

    public PaddingExtensionHandlerTest() {
    }

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
        msg.setPaddingBytes(new byte[6]);
        handler.adjustTLSContext(msg);
        assertEquals(context.getPaddingExtensionLength(), 6);
    }

    /**
     * Test of getParser method, of class PaddingExtensionHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[]{0, 15, 0, 6, 0, 0, 0, 0, 0, 0}, 0) instanceof PaddingExtensionParser);
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
