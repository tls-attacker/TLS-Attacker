/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.SrpServerKeyExchangeMessage;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

public class SrpServerKeyExchangeHandlerTest
    extends AbstractTlsMessageHandlerTest<SrpServerKeyExchangeMessage, SrpServerKeyExchangeHandler> {

    public SrpServerKeyExchangeHandlerTest() {
        super(SrpServerKeyExchangeMessage::new, SrpServerKeyExchangeHandler::new);
    }

    /**
     * Test of adjustTLSContext method, of class SrpServerKeyExchangeHandler.
     */

    @Test
    @Override
    public void testAdjustTLSContext() {
        SrpServerKeyExchangeMessage message = new SrpServerKeyExchangeMessage();
        message.setModulus(BigInteger.TEN.toByteArray());
        message.setGenerator(BigInteger.ONE.toByteArray());
        message.setSalt(BigInteger.TEN.toByteArray());
        message.setPublicKey(new byte[] { 0, 1, 2, 3 });
        context.setSelectedCipherSuite(CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA);
        message.prepareComputations();
        message.getComputations().setPrivateKey(BigInteger.ZERO);
        handler.adjustTLSContext(message);

        assertEquals(BigInteger.TEN, context.getSRPModulus());
        assertEquals(BigInteger.ONE, context.getSRPGenerator());
        assertArrayEquals(BigInteger.TEN.toByteArray(), context.getSRPServerSalt());
        assertEquals(new BigInteger(new byte[] { 0, 1, 2, 3 }), context.getServerSRPPublicKey());
        assertEquals(BigInteger.ZERO, context.getServerSRPPrivateKey());

        assertNull(context.getPreMasterSecret());
        assertNull(context.getMasterSecret());
    }

    @Test
    public void testAdjustTLSContextWithoutComputations() {
        SrpServerKeyExchangeMessage message = new SrpServerKeyExchangeMessage();
        message.setModulus(BigInteger.TEN.toByteArray());
        message.setGenerator(BigInteger.ONE.toByteArray());
        message.setSalt(BigInteger.TEN.toByteArray());
        message.setPublicKey(new byte[] { 0, 1, 2, 3 });
        handler.adjustTLSContext(message);

        assertEquals(BigInteger.TEN, context.getSRPModulus());
        assertEquals(BigInteger.ONE, context.getSRPGenerator());
        assertArrayEquals(BigInteger.TEN.toByteArray(), context.getSRPServerSalt());
        assertEquals(new BigInteger(new byte[] { 0, 1, 2, 3 }), context.getServerSRPPublicKey());
        assertNull(context.getServerSRPPrivateKey());

        assertNull(context.getPreMasterSecret());
        assertNull(context.getMasterSecret());
    }

}