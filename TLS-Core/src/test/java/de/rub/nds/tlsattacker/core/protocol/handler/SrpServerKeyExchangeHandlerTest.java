/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.SrpServerKeyExchangeMessage;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

public class SrpServerKeyExchangeHandlerTest
        extends AbstractProtocolMessageHandlerTest<
                SrpServerKeyExchangeMessage, SrpServerKeyExchangeHandler> {

    public SrpServerKeyExchangeHandlerTest() {
        super(SrpServerKeyExchangeMessage::new, SrpServerKeyExchangeHandler::new);
    }

    /** Test of adjustContext method, of class SrpServerKeyExchangeHandler. */
    @Test
    @Override
    public void testadjustContext() {
        SrpServerKeyExchangeMessage message = new SrpServerKeyExchangeMessage();
        message.setModulus(BigInteger.TEN.toByteArray());
        message.setGenerator(BigInteger.ONE.toByteArray());
        message.setSalt(BigInteger.TEN.toByteArray());
        message.setPublicKey(new byte[] {0, 1, 2, 3});
        context.setSelectedCipherSuite(CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA);
        message.prepareComputations();
        message.getComputations().setPrivateKey(BigInteger.ZERO);
        handler.adjustContext(message);

        assertEquals(BigInteger.TEN, context.getSRPModulus());
        assertEquals(BigInteger.ONE, context.getSRPGenerator());
        assertArrayEquals(BigInteger.TEN.toByteArray(), context.getSRPServerSalt());
        assertEquals(new BigInteger(new byte[] {0, 1, 2, 3}), context.getServerSRPPublicKey());
        assertEquals(BigInteger.ZERO, context.getServerSRPPrivateKey());

        assertNull(context.getPreMasterSecret());
        assertNull(context.getMasterSecret());
    }

    @Test
    public void testadjustContextWithoutComputations() {
        SrpServerKeyExchangeMessage message = new SrpServerKeyExchangeMessage();
        message.setModulus(BigInteger.TEN.toByteArray());
        message.setGenerator(BigInteger.ONE.toByteArray());
        message.setSalt(BigInteger.TEN.toByteArray());
        message.setPublicKey(new byte[] {0, 1, 2, 3});
        handler.adjustContext(message);

        assertEquals(BigInteger.TEN, context.getSRPModulus());
        assertEquals(BigInteger.ONE, context.getSRPGenerator());
        assertArrayEquals(BigInteger.TEN.toByteArray(), context.getSRPServerSalt());
        assertEquals(new BigInteger(new byte[] {0, 1, 2, 3}), context.getServerSRPPublicKey());
        assertNull(context.getServerSRPPrivateKey());

        assertNull(context.getPreMasterSecret());
        assertNull(context.getMasterSecret());
    }
}
