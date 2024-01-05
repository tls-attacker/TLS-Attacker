/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.DHEServerKeyExchangeParserTest;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class DHEServerKeyExchangeSerializerTest
        extends AbstractHandshakeMessageSerializerTest<
                DHEServerKeyExchangeMessage,
                DHEServerKeyExchangeSerializer<DHEServerKeyExchangeMessage>> {

    public DHEServerKeyExchangeSerializerTest() {
        super(
                DHEServerKeyExchangeMessage::new,
                DHEServerKeyExchangeSerializer::new,
                List.of(
                        (msg, obj) -> msg.setModulusLength((Integer) obj),
                        (msg, obj) -> msg.setModulus((byte[]) obj),
                        (msg, obj) -> msg.setGeneratorLength((Integer) obj),
                        (msg, obj) -> msg.setGenerator((byte[]) obj),
                        (msg, obj) -> msg.setPublicKeyLength((Integer) obj),
                        (msg, obj) -> msg.setPublicKey((byte[]) obj),
                        (msg, obj) -> msg.setSignatureAndHashAlgorithm((byte[]) obj),
                        (msg, obj) -> msg.setSignatureLength((Integer) obj),
                        (msg, obj) -> msg.setSignature((byte[]) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return DHEServerKeyExchangeParserTest.provideTestVectors();
    }
}
