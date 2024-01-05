/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ClientCertificateTypeExtensionParserTest;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class ClientCertificateTypeExtensionSerializerTest
        extends AbstractExtensionMessageSerializerTest<
                ClientCertificateTypeExtensionMessage, ClientCertificateTypeExtensionSerializer> {

    public ClientCertificateTypeExtensionSerializerTest() {
        super(
                ClientCertificateTypeExtensionMessage::new,
                ClientCertificateTypeExtensionSerializer::new,
                List.of(
                        (msg, obj) -> {
                            if (obj != null) {
                                msg.setCertificateTypesLength((Integer) obj);
                            }
                        },
                        (msg, obj) -> msg.setCertificateTypes((byte[]) obj),
                        (msg, obj) -> msg.setIsClientMessage((Boolean) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return ClientCertificateTypeExtensionParserTest.provideTestVectors();
    }
}
