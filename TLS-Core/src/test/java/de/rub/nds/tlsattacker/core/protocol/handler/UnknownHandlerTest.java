/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.UnknownMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.UnknownMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.UnknownMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class UnknownHandlerTest {

    private UnknownMessageHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new UnknownMessageHandler(context, ProtocolMessageType.UNKNOWN);
    }

    /**
     * Test of getParser method, of class UnknownHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[] { 0 }, 0) instanceof UnknownMessageParser);
    }

    /**
     * Test of getPreparator method, of class UnknownHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(
            new UnknownMessage(context.getConfig(), ProtocolMessageType.UNKNOWN)) instanceof UnknownMessagePreparator);
    }

    /**
     * Test of getSerializer method, of class UnknownHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(
            new UnknownMessage(context.getConfig(), ProtocolMessageType.UNKNOWN)) instanceof UnknownMessageSerializer);
    }

    /**
     * Test of adjustTLSContext method, of class UnknownHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        UnknownMessage message = new UnknownMessage(context.getConfig(), ProtocolMessageType.UNKNOWN);
        handler.adjustTLSContext(message);
    }

}
