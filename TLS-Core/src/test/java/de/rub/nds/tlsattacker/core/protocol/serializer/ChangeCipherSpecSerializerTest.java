/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ChangeCipherSpecParserTest;
import org.junit.jupiter.params.provider.Arguments;

import java.util.List;
import java.util.stream.Stream;

public class ChangeCipherSpecSerializerTest
    extends AbstractTlsMessageSerializerTest<ChangeCipherSpecMessage, ChangeCipherSpecSerializer> {

    public ChangeCipherSpecSerializerTest() {
        super(ChangeCipherSpecMessage::new, ChangeCipherSpecSerializer::new,
            List.of((msg, obj) -> msg.setCcsProtocolType((byte[]) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return ChangeCipherSpecParserTest.provideTestVectors();
    }
}
