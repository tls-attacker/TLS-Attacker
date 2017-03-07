/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler;

import de.rub.nds.tlsattacker.tls.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.ApplicationMessageParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.ECDHEServerKeyExchangeParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.ECDHClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.tls.protocol.preparator.ECDHEServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.ECDHClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.ECDHEServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ECDHEServerKeyExchangeHandlerTest {

    private ECDHEServerKeyExchangeHandler handler;
    private TlsContext context;

    public ECDHEServerKeyExchangeHandlerTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new ECDHEServerKeyExchangeHandler(context);

    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getParser method, of class ECDHEServerKeyExchangeHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof ECDHEServerKeyExchangeParser);
    }

    /**
     * Test of getPreparator method, of class ECDHEServerKeyExchangeHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new ECDHEServerKeyExchangeMessage()) instanceof ECDHEServerKeyExchangePreparator);
    }

    /**
     * Test of getSerializer method, of class ECDHEServerKeyExchangeHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new ECDHEServerKeyExchangeMessage()) instanceof ECDHEServerKeyExchangeSerializer);
    }

    /**
     * Test of adjustTLSContext method, of class ECDHEServerKeyExchangeHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        ECDHEServerKeyExchangeMessage message = new ECDHEServerKeyExchangeMessage();
        message.getComputations().setPremasterSecret(new byte[] { 0, 1, 2, 3 });
        message.getComputations().setMasterSecret(new byte[] { 4, 5, 6 });
        handler.adjustTLSContext(message);
        assertArrayEquals(new byte[] { 0, 1, 2, 3 }, context.getPreMasterSecret());
        assertArrayEquals(new byte[] { 4, 5, 6 }, context.getMasterSecret());
    }

    @Test
    public void testAdjustTLSContextWithoutComputations() {
        ECDHEServerKeyExchangeMessage message = new ECDHEServerKeyExchangeMessage();
        handler.adjustTLSContext(message);
        assertTrue(context.getPreMasterSecret().length == 0);
        assertTrue(context.getMasterSecret().length == 0);
    }

}
