/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RecordSizeLimitExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.RecordSizeLimitExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.RecordSizeLimitExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.RecordSizeLimitExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class RecordSizeLimitExtensionHandlerTest {

    private RecordSizeLimitExtensionHandler handler;

    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new RecordSizeLimitExtensionHandler(context);
    }

    /**
     * Test of adjustTLSContext method, of class RecordSizeLimitExtensionHandler.
     */
    @Test
    public void testAdjustTLSContextClient() {
        RecordSizeLimitExtensionMessage msg = new RecordSizeLimitExtensionMessage();
        msg.setRecordSizeLimit(new byte[] { (byte) 0x05, (byte) 0x39 });
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        assertNull(context.getClientRecordSizeLimit());
        assertNull(context.getServerRecordSizeLimit());
        handler.adjustTLSContext(msg);
        assertTrue(context.getClientRecordSizeLimit() == 1337);
        assertNull(context.getServerRecordSizeLimit());
    }

    @Test
    public void testAdjustTLSContextServer() {
        RecordSizeLimitExtensionMessage msg = new RecordSizeLimitExtensionMessage();
        msg.setRecordSizeLimit(new byte[] { (byte) 0x05, (byte) 0x39 });
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        assertNull(context.getClientRecordSizeLimit());
        assertNull(context.getServerRecordSizeLimit());
        handler.adjustTLSContext(msg);
        assertNull(context.getClientRecordSizeLimit());
        assertTrue(context.getServerRecordSizeLimit() == 1337);
    }

    @Test(expected = AdjustmentException.class)
    public void testAdjustTLSContextInvalidSize() {
        RecordSizeLimitExtensionMessage msg = new RecordSizeLimitExtensionMessage();
        msg.setRecordSizeLimit(new byte[] { (byte) 0x05, (byte) 0x39, (byte) 0x00 });
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        assertNull(context.getClientRecordSizeLimit());
        assertNull(context.getServerRecordSizeLimit());
        handler.adjustTLSContext(msg);
    }

    public void testAdjustTLSContextSizeTooSmall() {
        RecordSizeLimitExtensionMessage msg = new RecordSizeLimitExtensionMessage();
        msg.setRecordSizeLimit(new byte[] { (byte) 0x00, (byte) 0x2A });
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        assertNull(context.getClientRecordSizeLimit());
        assertNull(context.getServerRecordSizeLimit());
        handler.adjustTLSContext(msg);
        assertNull(context.getClientRecordSizeLimit());
        assertNull(context.getServerRecordSizeLimit());
    }

    /**
     * Test of getParser method, of class RecordSizeLimitExtensionHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[] { 0, 1, 2, 3 }, 0,
            context.getConfig()) instanceof RecordSizeLimitExtensionParser);
    }

    /**
     * Test of getPreparator method, of class RecordSizeLimitExtensionHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(
            handler.getPreparator(new RecordSizeLimitExtensionMessage()) instanceof RecordSizeLimitExtensionPreparator);
    }

    /**
     * Test of getSerializer method, of class RecordSizeLimitExtensionHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(
            handler.getSerializer(new RecordSizeLimitExtensionMessage()) instanceof RecordSizeLimitExtensionSerializer);
    }

}
