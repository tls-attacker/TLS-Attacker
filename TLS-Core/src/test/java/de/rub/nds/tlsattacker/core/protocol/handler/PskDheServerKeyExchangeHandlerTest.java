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
import de.rub.nds.tlsattacker.core.protocol.message.PskDheServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.PskDheServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PskDheServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PskDheServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.math.BigInteger;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class PskDheServerKeyExchangeHandlerTest {

    private PskDheServerKeyExchangeHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new PskDheServerKeyExchangeHandler(context);

    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getParser method, of class PskDheServerKeyExchangeHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof PskDheServerKeyExchangeParser);
    }

    /**
     * Test of getPreparator method, of class PskDheServerKeyExchangeHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new PskDheServerKeyExchangeMessage()) instanceof PskDheServerKeyExchangePreparator);
    }

    /**
     * Test of getSerializer method, of class PskDheServerKeyExchangeHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new PskDheServerKeyExchangeMessage()) instanceof PskDheServerKeyExchangeSerializer);
    }

    /**
     * Test of adjustTLSContext method, of class PskDheServerKeyExchangeHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        PskDheServerKeyExchangeMessage message = new PskDheServerKeyExchangeMessage();
        message.setModulus(BigInteger.TEN.toByteArray());
        message.setGenerator(BigInteger.ONE.toByteArray());
        message.setPublicKey(new byte[] { 0, 1, 2, 3 });
        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA);
        message.prepareComputations();
        message.getComputations().setPrivateKey(BigInteger.ZERO);
        handler.adjustTLSContext(message);
        assertNull(context.getPreMasterSecret());
    }

    @Test
    public void testAdjustTLSContextWithoutComputations() {
        PskDheServerKeyExchangeMessage message = new PskDheServerKeyExchangeMessage();
        message.setModulus(BigInteger.TEN.toByteArray());
        message.setGenerator(BigInteger.ONE.toByteArray());
        message.setPublicKey(new byte[] { 0, 1, 2, 3 });
        handler.adjustTLSContext(message);
        assertNull(context.getPreMasterSecret());
        assertNull(context.getMasterSecret());
    }
}
