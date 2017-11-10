/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.MaxFragmentLengthExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.MaxFragmentLengthExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.MaxFragmentLengthExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class MaxFragmentLengthExtensionHandlerTest {

    private MaxFragmentLengthExtensionHandler handler;

    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new MaxFragmentLengthExtensionHandler(context);
    }

    /**
     * Test of adjustTLSContext method, of class
     * MaxFragmentLengthExtensionHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        MaxFragmentLengthExtensionMessage msg = new MaxFragmentLengthExtensionMessage();
        msg.setMaxFragmentLength(new byte[] { 1 });
        handler.adjustTLSContext(msg);
        assertTrue(context.getMaxFragmentLength() == MaxFragmentLength.TWO_9);
    }

    @Test
    public void testUndefinedAdjustment() {
        MaxFragmentLengthExtensionMessage msg = new MaxFragmentLengthExtensionMessage();
        msg.setMaxFragmentLength(new byte[] { 77 });
        handler.adjustTLSContext(msg);
        assertNull(context.getMaxFragmentLength());
    }

    /**
     * Test of getParser method, of class MaxFragmentLengthExtensionHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[] { 0, 1, 2, 3 }, 0) instanceof MaxFragmentLengthExtensionParser);
    }

    /**
     * Test of getPreparator method, of class MaxFragmentLengthExtensionHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new MaxFragmentLengthExtensionMessage()) instanceof MaxFragmentLengthExtensionPreparator);
    }

    /**
     * Test of getSerializer method, of class MaxFragmentLengthExtensionHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new MaxFragmentLengthExtensionMessage()) instanceof MaxFragmentLengthExtensionSerializer);
    }

}
