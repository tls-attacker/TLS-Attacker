/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.KeyShareExtensionParserTest;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.jupiter.params.provider.Arguments;

import java.util.List;
import java.util.stream.Stream;

public class KeyShareExtensionSerializerTest
    extends AbstractExtensionMessageSerializerTest<KeyShareExtensionMessage, KeyShareExtensionSerializer> {

    public KeyShareExtensionSerializerTest() {
        super(KeyShareExtensionMessage::new, (msg) -> new KeyShareExtensionSerializer(msg, ConnectionEndType.CLIENT),
            List.of((msg, obj) -> msg.setKeyShareListLength((Integer) obj),
                (msg, obj) -> msg.setKeyShareListBytes((byte[]) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return KeyShareExtensionParserTest.provideTestVectors();
    }
}
