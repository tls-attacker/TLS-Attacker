/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SignatureAndHashAlgorithmsExtensionParserTest;
import org.junit.jupiter.params.provider.Arguments;

import java.util.List;
import java.util.stream.Stream;

public class SignatureAndHashAlgorithmsExtensionSerializerTest extends AbstractExtensionMessageSerializerTest<
    SignatureAndHashAlgorithmsExtensionMessage, SignatureAndHashAlgorithmsExtensionSerializer> {

    public SignatureAndHashAlgorithmsExtensionSerializerTest() {
        super(SignatureAndHashAlgorithmsExtensionMessage::new, SignatureAndHashAlgorithmsExtensionSerializer::new,
            List.of((msg, obj) -> msg.setSignatureAndHashAlgorithmsLength((Integer) obj),
                (msg, obj) -> msg.setSignatureAndHashAlgorithms((byte[]) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return SignatureAndHashAlgorithmsExtensionParserTest.provideTestVectors();
    }
}
