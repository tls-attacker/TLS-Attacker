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

public class SSL2ClientHelloMessageTest extends AbstractMessageTest<SSL2ClientHelloMessage> {

    public SSL2ClientHelloMessageTest() {
        super(
                SSL2ClientHelloMessage::new,
                "SSL2ClientHelloMessage:\n"
                        + "  Protocol Version: %s\n"
                        + "  Type: %s\n"
                        + "  Supported CipherSuites: %s\n"
                        + "  Challenge: %s\n"
                        + "  SessionID: %s");
    }

    public static Stream<Arguments> provideToStringTestVectors() {
        return Stream.of(Arguments.of(new Object[] {null, null, null, null, null}, null));
    }
}
