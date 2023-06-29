/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.HeartbeatExtensionParserTest;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class HeartbeatExtensionSerializerTest
        extends AbstractExtensionMessageSerializerTest<
                HeartbeatExtensionMessage, HeartbeatExtensionSerializer> {

    public HeartbeatExtensionSerializerTest() {
        super(
                HeartbeatExtensionMessage::new,
                HeartbeatExtensionSerializer::new,
                List.of((msg, obj) -> msg.setHeartbeatMode((byte[]) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return HeartbeatExtensionParserTest.provideTestVectors();
    }
}
