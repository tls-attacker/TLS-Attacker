/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.HelloRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.HelloRequestParserTest;
import org.junit.jupiter.params.provider.Arguments;

import java.util.stream.Stream;

public class HelloRequestSerializerTest
    extends AbstractHandshakeMessageSerializerTest<HelloRequestMessage, HelloRequestSerializer> {

    public HelloRequestSerializerTest() {
        super(HelloRequestMessage::new, HelloRequestSerializer::new);
    }

    public static Stream<Arguments> provideTestVectors() {
        return HelloRequestParserTest.provideTestVectors();
    }
}
