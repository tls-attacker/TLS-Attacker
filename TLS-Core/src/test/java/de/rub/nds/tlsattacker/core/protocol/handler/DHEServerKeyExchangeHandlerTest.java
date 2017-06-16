/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.handler.DHEServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.DHEServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.DHEServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.DHEServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.math.BigInteger;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class DHEServerKeyExchangeHandlerTest {

    private DHEServerKeyExchangeHandler handler;
    private TlsContext context;

    public DHEServerKeyExchangeHandlerTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new DHEServerKeyExchangeHandler(context);

    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getParser method, of class DHEServerKeyExchangeHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof DHEServerKeyExchangeParser);
    }

    /**
     * Test of getPreparator method, of class DHEServerKeyExchangeHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new DHEServerKeyExchangeMessage()) instanceof DHEServerKeyExchangePreparator);
    }

    /**
     * Test of getSerializer method, of class DHEServerKeyExchangeHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new DHEServerKeyExchangeMessage()) instanceof DHEServerKeyExchangeSerializer);
    }

    /**
     * Test of adjustTLSContext method, of class DHEServerKeyExchangeHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        DHEServerKeyExchangeMessage message = new DHEServerKeyExchangeMessage();
        message.setModulus(BigInteger.TEN.toByteArray());
        message.setGenerator(BigInteger.ONE.toByteArray());
        message.setPublicKey(new byte[] { 0, 1, 2, 3 });
        message.prepareComputations();
        message.getComputations().setPrivateKey(new BigInteger("123"));
        message.getComputations().setPremasterSecret(new byte[] { 0, 1, 2, 3 });
        message.getComputations().setMasterSecret(new byte[] { 4, 5, 6 });
        handler.adjustTLSContext(message);
        assertNull(context.getPreMasterSecret());
        assertNull(context.getMasterSecret());
    }

    @Test
    public void testAdjustTLSContextWithoutComputations() {
        DHEServerKeyExchangeMessage message = new DHEServerKeyExchangeMessage();
        message.setModulus(BigInteger.TEN.toByteArray());
        message.setGenerator(BigInteger.ONE.toByteArray());
        message.setPublicKey(new byte[] { 0, 1, 2, 3 });
        handler.adjustTLSContext(message);
        assertNull(context.getPreMasterSecret());
        assertNull(context.getMasterSecret());
    }
}
