/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import org.junit.jupiter.params.provider.Arguments;

import java.util.stream.Stream;

public class ECDHEServerKeyExchangeMessageTest
        extends AbstractMessageTest<ECDHEServerKeyExchangeMessage> {

    public ECDHEServerKeyExchangeMessageTest() {
        super(
                ECDHEServerKeyExchangeMessage::new,
                "ECDHEServerKeyExchangeMessage:\n"
                        + "  Curve Type: %s\n"
                        + "  Named Curve: %s\n"
                        + "  Public Key: %s\n"
                        + "  Signature and Hash Algorithm: %s\n"
                        + "  Signature: %s");
    }

    public static Stream<Arguments> provideToStringTestVectors() {
        return Stream.of(Arguments.of(new Object[] {null, null, null, null, null}, null));
    }
}
