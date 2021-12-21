/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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
        assertArrayEquals(BigInteger.TEN.toByteArray(), context.getServerDhModulus().toByteArray());
        assertArrayEquals(BigInteger.ONE.toByteArray(), context.getServerDhGenerator().toByteArray());
        assertArrayEquals(new byte[] { 1, 2, 3 }, context.getServerDhPublicKey().toByteArray());
    }

    @Test
    public void testAdjustTLSContextWithoutComputations() {
        DHEServerKeyExchangeMessage message = new DHEServerKeyExchangeMessage();
        message.setModulus(BigInteger.TEN.toByteArray());
        message.setGenerator(BigInteger.ONE.toByteArray());
        message.setPublicKey(new byte[] { 1, 2, 3 });
        handler.adjustTLSContext(message);
        assertArrayEquals(BigInteger.TEN.toByteArray(), context.getServerDhModulus().toByteArray());
        assertArrayEquals(BigInteger.ONE.toByteArray(), context.getServerDhGenerator().toByteArray());
        assertArrayEquals(new byte[] { 1, 2, 3 }, context.getServerDhPublicKey().toByteArray());
    }

    @Test
    public void testAdjustTlsContextWithFFDHEGroup() {
        DHEServerKeyExchangeMessage message = new DHEServerKeyExchangeMessage();
        FFDHEGroup group = GroupFactory.getGroup(NamedGroup.FFDHE2048);
        message.setModulus(group.getP().toByteArray());
        message.setGenerator(group.getG().toByteArray());
        message.setPublicKey(new byte[] { 1, 2, 3 });
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
        message.prepareComputations();
        message.getComputations().setPrivateKey(BigInteger.ZERO);
        handler.adjustTLSContext(message);
        assertEquals(BigInteger.TWO, context.getServerDhGenerator());
        BigInteger expectedP = new BigInteger(
            "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF",
            16);
        assertEquals(expectedP, context.getServerDhModulus());
        assertArrayEquals(new byte[] { 1, 2, 3 }, context.getServerDhPublicKey().toByteArray());
    }
}
