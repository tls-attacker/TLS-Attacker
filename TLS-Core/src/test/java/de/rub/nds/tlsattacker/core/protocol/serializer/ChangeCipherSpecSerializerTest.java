/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ChangeCipherSpecParserTest;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class ChangeCipherSpecSerializerTest
        extends AbstractProtocolMessageSerializerTest<
                ChangeCipherSpecMessage, ChangeCipherSpecSerializer> {

    public ChangeCipherSpecSerializerTest() {
        super(
                ChangeCipherSpecMessage::new,
                ChangeCipherSpecSerializer::new,
                List.of((msg, obj) -> msg.setCcsProtocolType((byte[]) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return ChangeCipherSpecParserTest.provideTestVectors();
    }
}
