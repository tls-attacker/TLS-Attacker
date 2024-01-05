/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.PWDClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.PWDClientKeyExchangeParserTest;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class PWDClientKeyExchangeSerializerTest
        extends AbstractHandshakeMessageSerializerTest<
                PWDClientKeyExchangeMessage, PWDClientKeyExchangeSerializer> {

    public PWDClientKeyExchangeSerializerTest() {
        super(
                PWDClientKeyExchangeMessage::new,
                PWDClientKeyExchangeSerializer::new,
                List.of(
                        (msg, obj) -> msg.setElementLength((Integer) obj),
                        (msg, obj) -> msg.setElement((byte[]) obj),
                        (msg, obj) -> msg.setScalarLength((Integer) obj),
                        (msg, obj) -> msg.setScalar((byte[]) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return PWDClientKeyExchangeParserTest.provideTestVectors();
    }
}
