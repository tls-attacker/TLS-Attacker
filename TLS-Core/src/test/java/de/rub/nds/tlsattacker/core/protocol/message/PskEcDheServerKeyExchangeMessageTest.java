/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class PskEcDheServerKeyExchangeMessageTest
        extends AbstractMessageTest<PskEcDheServerKeyExchangeMessage> {

    public PskEcDheServerKeyExchangeMessageTest() {
        super(
                PskEcDheServerKeyExchangeMessage::new,
                "PskEcDheServerKeyExchangeMessage:\n"
                        + "  Curve Type: %s\n"
                        + "  Named Group: %s\n"
                        + "  Public Key: %s");
    }

    public static Stream<Arguments> provideToStringTestVectors() {
        return Stream.of(Arguments.of(new Object[] {null, null, null}, null));
    }
}
