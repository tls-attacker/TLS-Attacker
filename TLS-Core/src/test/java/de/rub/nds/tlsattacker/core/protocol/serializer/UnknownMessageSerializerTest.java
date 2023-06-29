/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.UnknownMessageParserTest;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class UnknownMessageSerializerTest
        extends AbstractProtocolMessageSerializerTest<UnknownMessage, UnknownMessageSerializer> {

    public UnknownMessageSerializerTest() {
        super(
                UnknownMessage::new,
                UnknownMessageSerializer::new,
                List.of((msg, obj) -> msg.setCompleteResultingMessage((byte[]) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return UnknownMessageParserTest.provideTestVectors();
    }
}
