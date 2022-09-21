/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message;

import org.junit.jupiter.params.provider.Arguments;

import java.util.stream.Stream;

public class ServerHelloMessageTest extends AbstractMessageTest<ServerHelloMessage> {

    public ServerHelloMessageTest() {
        super(ServerHelloMessage::new,
            "HandshakeMessage:\n" + "  Type: %s\n" + "  Length: %s\n" + "  Protocol Version: %s\n"
                + "  Server Unix Time: %s\n" + "  Server Random: %s\n" + "  Session ID: %s\n"
                + "  Selected Cipher Suite: %s\n" + "  Selected Compression Method: %s\n" + "  Extensions: %s");
    }

    public static Stream<Arguments> provideToStringTestVectors() {
        return Stream.of(Arguments.of(new Object[] { null, null, null, null, null, null, null, null, null }, null));
    }
}
