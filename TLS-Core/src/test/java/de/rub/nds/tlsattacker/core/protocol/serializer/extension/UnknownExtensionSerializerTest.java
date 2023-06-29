/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.UnknownExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.UnknownExtensionParserTest;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class UnknownExtensionSerializerTest
        extends AbstractExtensionMessageSerializerTest<
                UnknownExtensionMessage, UnknownExtensionSerializer> {

    public UnknownExtensionSerializerTest() {
        super(
                UnknownExtensionMessage::new,
                UnknownExtensionSerializer::new,
                List.of(
                        (msg, obj) -> {
                            if (obj != null) {
                                msg.setExtensionData((byte[]) obj);
                            }
                        }));
    }

    public static Stream<Arguments> provideTestVectors() {
        return UnknownExtensionParserTest.provideTestVectors();
    }
}
