/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ServerHelloParserTest;
import org.junit.jupiter.params.provider.Arguments;

import java.util.List;
import java.util.stream.Stream;

public class ServerHelloSerializerTest
    extends AbstractHandshakeMessageSerializerTest<ServerHelloMessage, ServerHelloSerializer> {

    public ServerHelloSerializerTest() {
        super(ServerHelloMessage::new, ServerHelloSerializer::new,
            List.of((msg, obj) -> msg.setProtocolVersion((byte[]) obj), (msg, obj) -> msg.setUnixTime((byte[]) obj),
                (msg, obj) -> msg.setRandom((byte[]) obj), (msg, obj) -> msg.setSessionIdLength((Integer) obj),
                (msg, obj) -> msg.setSessionId((byte[]) obj), (msg, obj) -> msg.setSelectedCipherSuite((byte[]) obj),
                (msg, obj) -> msg.setSelectedCompressionMethod((Byte) obj),
                (msg, obj) -> msg.setExtensionsLength((Integer) obj),
                (msg, obj) -> msg.setExtensionBytes((byte[]) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return ServerHelloParserTest.provideTestVectors();
    }
}
