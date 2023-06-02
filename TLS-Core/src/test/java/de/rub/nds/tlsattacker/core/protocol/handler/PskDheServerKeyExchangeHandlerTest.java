/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import static org.junit.jupiter.api.Assertions.assertNull;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.PskDheServerKeyExchangeMessage;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

public class PskDheServerKeyExchangeHandlerTest
        extends AbstractProtocolMessageHandlerTest<
                PskDheServerKeyExchangeMessage, PskDheServerKeyExchangeHandler> {

    public PskDheServerKeyExchangeHandlerTest() {
        super(PskDheServerKeyExchangeMessage::new, PskDheServerKeyExchangeHandler::new);
    }

    /** Test of adjustContext method, of class PskDheServerKeyExchangeHandler. */
    @Test
    @Override
    public void testadjustContext() {
        PskDheServerKeyExchangeMessage message = new PskDheServerKeyExchangeMessage();
        message.setModulus(BigInteger.TEN.toByteArray());
        message.setGenerator(BigInteger.ONE.toByteArray());
        message.setPublicKey(new byte[] {0, 1, 2, 3});
        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA);
        message.prepareComputations();
        message.getComputations().setPrivateKey(BigInteger.ZERO);
        handler.adjustContext(message);
        assertNull(context.getPreMasterSecret());
    }

    @Test
    public void testadjustContextWithoutComputations() {
        PskDheServerKeyExchangeMessage message = new PskDheServerKeyExchangeMessage();
        message.setModulus(BigInteger.TEN.toByteArray());
        message.setGenerator(BigInteger.ONE.toByteArray());
        message.setPublicKey(new byte[] {0, 1, 2, 3});
        handler.adjustContext(message);
        assertNull(context.getPreMasterSecret());
        assertNull(context.getMasterSecret());
    }
}
