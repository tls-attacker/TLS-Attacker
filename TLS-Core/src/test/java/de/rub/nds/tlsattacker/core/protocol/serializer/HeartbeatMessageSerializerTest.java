/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.HeartbeatMessageParserTest;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class HeartbeatMessageSerializerTest
        extends AbstractProtocolMessageSerializerTest<
                HeartbeatMessage, HeartbeatMessageSerializer> {

    public HeartbeatMessageSerializerTest() {
        super(
                HeartbeatMessage::new,
                HeartbeatMessageSerializer::new,
                List.of(
                        (msg, obj) -> msg.setHeartbeatMessageType((Byte) obj),
                        (msg, obj) -> msg.setPayloadLength((Integer) obj),
                        (msg, obj) -> msg.setPayload((byte[]) obj),
                        (msg, obj) -> msg.setPadding((byte[]) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return HeartbeatMessageParserTest.provideTestVectors();
    }
}
