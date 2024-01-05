/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import org.junit.jupiter.api.Test;

public class HelloVerifyRequestPreparatorTest
        extends AbstractProtocolMessagePreparatorTest<
                HelloVerifyRequestMessage, HelloVerifyRequestPreparator> {

    public HelloVerifyRequestPreparatorTest() {
        super(HelloVerifyRequestMessage::new, HelloVerifyRequestPreparator::new);
    }

    /** Test of prepareHandshakeMessageContents method, of class HelloVerifyRequestPreparator. */
    @Test
    @Override
    public void testPrepare() {
        context.getConfig().setDtlsDefaultCookieLength(10);
        context.getConfig().setHighestProtocolVersion(ProtocolVersion.DTLS12);
        preparator.prepare();
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("60B420BB3851D9D47ACB"),
                message.getCookie().getValue());
        assertEquals(10, (byte) message.getCookieLength().getValue());
        assertArrayEquals(
                ProtocolVersion.DTLS12.getValue(), message.getProtocolVersion().getValue());
    }
}
