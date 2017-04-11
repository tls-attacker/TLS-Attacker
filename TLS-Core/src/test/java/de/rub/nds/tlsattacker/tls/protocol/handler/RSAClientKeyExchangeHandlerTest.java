/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler;

import de.rub.nds.tlsattacker.tls.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.HelloVerifyRequestParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.RSAClientKeyExchangeParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.FinishedMessagePreparator;
import de.rub.nds.tlsattacker.tls.protocol.preparator.RSAClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.RSAClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class RSAClientKeyExchangeHandlerTest {

    private RSAClientKeyExchangeHandler handler;
    private TlsContext context;

    public RSAClientKeyExchangeHandlerTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new RSAClientKeyExchangeHandler(context);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getParser method, of class RSAClientKeyExchangeHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof RSAClientKeyExchangeParser);
    }

    /**
     * Test of getPreparator method, of class RSAClientKeyExchangeHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new RSAClientKeyExchangeMessage()) instanceof RSAClientKeyExchangePreparator);
    }

    /**
     * Test of getSerializer method, of class RSAClientKeyExchangeHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new RSAClientKeyExchangeMessage()) instanceof RSAClientKeyExchangeSerializer);
    }

    /**
     * Test of adjustTLSContext method, of class RSAClientKeyExchangeHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        RSAClientKeyExchangeMessage message = new RSAClientKeyExchangeMessage();
        message.prepareComputations();
        message.getComputations().setPremasterSecret(new byte[] { 0, 1, 2, 3 });
        message.getComputations().setMasterSecret(new byte[] { 4, 5, 6 });
        handler.adjustTLSContext(message);
        assertArrayEquals(new byte[] { 0, 1, 2, 3 }, context.getPreMasterSecret());
        assertArrayEquals(new byte[] { 4, 5, 6 }, context.getMasterSecret());
    }

    @Test
    public void testAdjustTLSContextWithoutComputations() {
        RSAClientKeyExchangeMessage message = new RSAClientKeyExchangeMessage();
        handler.adjustTLSContext(message);
        assertNull(context.getPreMasterSecret());
        assertNull(context.getMasterSecret());
    }

}
