/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ChangeCipherSpecParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ChangeCipherSpecPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ChangeCipherSpecSerializer;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class ChangeCipherSpecHandlerTest {

    private ChangeCipherSpecHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new ChangeCipherSpecHandler(context);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getParser method, of class ChangeCipherSpecHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof ChangeCipherSpecParser);
    }

    /**
     * Test of getPreparator method, of class ChangeCipherSpecHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new ChangeCipherSpecMessage()) instanceof ChangeCipherSpecPreparator);
    }

    /**
     * Test of getSerializer method, of class ChangeCipherSpecHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new ChangeCipherSpecMessage()) instanceof ChangeCipherSpecSerializer);
    }

    /**
     * Test of adjustTLSContext method, of class ChangeCipherSpecHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        ChangeCipherSpecMessage message = new ChangeCipherSpecMessage();
        context.setRecordLayer(new TlsRecordLayer(context));
        context.setSelectedCipherSuite(CipherSuite.getImplemented().get(0));
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        handler.adjustTLSContext(message);
        // TODO check that change did actually work
    }

}
