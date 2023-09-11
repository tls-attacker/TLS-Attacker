/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.protocol.crypto.ffdh.FFDHGroup;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

public class DHEServerKeyExchangeHandlerTest
        extends AbstractProtocolMessageHandlerTest<
                DHEServerKeyExchangeMessage,
                ServerKeyExchangeHandler<DHEServerKeyExchangeMessage>> {

    DHEServerKeyExchangeHandlerTest() {
        super(DHEServerKeyExchangeMessage::new, DHEServerKeyExchangeHandler::new);
    }

    /** Test of adjustContext method, of class DHEServerKeyExchangeHandler. */
    @Test
    @Override
    public void testadjustContext() {
        DHEServerKeyExchangeMessage message = new DHEServerKeyExchangeMessage();
        message.setModulus(BigInteger.TEN.toByteArray());
        message.setGenerator(BigInteger.ONE.toByteArray());
        message.setPublicKey(new byte[] {1, 2, 3});
        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
        message.prepareKeyExchangeComputations();
        message.getKeyExchangeComputations().setPrivateKey(BigInteger.ZERO);
        handler.adjustContext(message);
        assertEquals(BigInteger.TEN, context.getServerEphemeralDhModulus());
        assertEquals(BigInteger.ONE, context.getServerEphemeralDhGenerator());
        assertArrayEquals(
                new byte[] {1, 2, 3}, context.getServerEphemeralDhPublicKey().toByteArray());
    }

    @Test
    public void testadjustContextWithoutComputations() {
        DHEServerKeyExchangeMessage message = new DHEServerKeyExchangeMessage();
        message.setModulus(BigInteger.TEN.toByteArray());
        message.setGenerator(BigInteger.ONE.toByteArray());
        message.setPublicKey(new byte[] {1, 2, 3});
        handler.adjustContext(message);
        assertEquals(BigInteger.TEN, context.getServerEphemeralDhModulus());
        assertEquals(BigInteger.ONE, context.getServerEphemeralDhGenerator());
        assertArrayEquals(
                new byte[] {1, 2, 3}, context.getServerEphemeralDhPublicKey().toByteArray());
    }

    @ParameterizedTest
    @EnumSource(value = NamedGroup.class, names = "^FFDHE[0-9]*", mode = EnumSource.Mode.MATCH_ANY)
    public void testadjustContextWithFFDHEGroup(NamedGroup providedNamedGroup) {
        DHEServerKeyExchangeMessage message = new DHEServerKeyExchangeMessage();
        FFDHGroup group = (FFDHGroup) providedNamedGroup.getGroupParameters();
        message.setModulus(group.getModulus().toByteArray());
        message.setGenerator(group.getGenerator().toByteArray());
        message.setPublicKey(new byte[] {1, 2, 3});
        handler.adjustContext(message);
        assertEquals(group.getGenerator(), context.getServerEphemeralDhGenerator());
        assertEquals(group.getModulus(), context.getServerEphemeralDhModulus());
        assertArrayEquals(
                new byte[] {1, 2, 3}, context.getServerEphemeralDhPublicKey().toByteArray());
        assertEquals(context.getSelectedGroup(), providedNamedGroup);
    }
}
