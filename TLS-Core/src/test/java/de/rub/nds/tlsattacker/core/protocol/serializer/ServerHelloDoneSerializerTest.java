/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ServerHelloDoneParserTest;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class ServerHelloDoneSerializerTest
        extends AbstractHandshakeMessageSerializerTest<
                ServerHelloDoneMessage, ServerHelloDoneSerializer> {

    public ServerHelloDoneSerializerTest() {
        super(ServerHelloDoneMessage::new, ServerHelloDoneSerializer::new);
    }

    public static Stream<Arguments> provideTestVectors() {
        return ServerHelloDoneParserTest.provideTestVectors();
    }
}
