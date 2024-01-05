/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class ServerHelloDoneParserTest
        extends AbstractHandshakeMessageParserTest<ServerHelloDoneMessage, ServerHelloDoneParser> {

    public ServerHelloDoneParserTest() {
        super(ServerHelloDoneMessage.class, ServerHelloDoneParser::new);
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        ArrayConverter.hexStringToByteArray("0e000000"),
                        List.of(HandshakeMessageType.SERVER_HELLO_DONE.getValue(), 0)),
                Arguments.of(
                        ProtocolVersion.TLS11,
                        ArrayConverter.hexStringToByteArray("0e000000"),
                        List.of(HandshakeMessageType.SERVER_HELLO_DONE.getValue(), 0)),
                Arguments.of(
                        ProtocolVersion.TLS10,
                        ArrayConverter.hexStringToByteArray("0e000000"),
                        List.of(HandshakeMessageType.SERVER_HELLO_DONE.getValue(), 0)));
    }
}
