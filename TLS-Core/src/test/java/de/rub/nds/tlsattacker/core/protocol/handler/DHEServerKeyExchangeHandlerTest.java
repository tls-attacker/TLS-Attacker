/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.ffdh.FFDHEGroup;
import de.rub.nds.tlsattacker.core.crypto.ffdh.GroupFactory;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.DHEServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.DHEServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.DHEServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.math.BigInteger;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class DHEServerKeyExchangeHandlerTest {

    private DHEServerKeyExchangeHandler handler;
    private TlsContext context;

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
        message.setPublicKey(new byte[] { 1, 2, 3 });
        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
        message.prepareComputations();
        message.getComputations().setPrivateKey(BigInteger.ZERO);
        handler.adjustTLSContext(message);
        assertEquals(BigInteger.TEN, context.getServerDhModulus());
        assertEquals(BigInteger.ONE, context.getServerDhGenerator());
        assertArrayEquals(new byte[] { 1, 2, 3 }, context.getServerDhPublicKey().toByteArray());
    }

    @Test
    public void testAdjustTLSContextWithoutComputations() {
        DHEServerKeyExchangeMessage message = new DHEServerKeyExchangeMessage();
        message.setModulus(BigInteger.TEN.toByteArray());
        message.setGenerator(BigInteger.ONE.toByteArray());
        message.setPublicKey(new byte[] { 1, 2, 3 });
        handler.adjustTLSContext(message);
        assertEquals(BigInteger.TEN, context.getServerDhModulus());
        assertEquals(BigInteger.ONE, context.getServerDhGenerator());
        assertArrayEquals(new byte[] { 1, 2, 3 }, context.getServerDhPublicKey().toByteArray());
    }

    @Test
    public void testAdjustTlsContextWithFFDHEGroup() {
        DHEServerKeyExchangeMessage message = new DHEServerKeyExchangeMessage();
        for (NamedGroup namedGroup : NamedGroup.getImplemented()) {
            if (namedGroup.isDhGroup()) {
                FFDHEGroup group = GroupFactory.getGroup(namedGroup);
                message.setModulus(group.getP().toByteArray());
                message.setGenerator(group.getG().toByteArray());
                message.setPublicKey(new byte[] { 1, 2, 3 });
                handler.adjustTLSContext(message);
                assertEquals(group.getG(), context.getServerDhGenerator());
                assertEquals(group.getP(), context.getServerDhModulus());
                assertArrayEquals(new byte[] { 1, 2, 3 }, context.getServerDhPublicKey().toByteArray());
                assertEquals(context.getSelectedGroup(), namedGroup);
            }
        }
    }
}
