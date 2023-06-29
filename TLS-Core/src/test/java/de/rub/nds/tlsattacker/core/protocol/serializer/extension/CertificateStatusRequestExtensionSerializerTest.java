/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.CertificateStatusRequestExtensionParserTest;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class CertificateStatusRequestExtensionSerializerTest
        extends AbstractExtensionMessageSerializerTest<
                CertificateStatusRequestExtensionMessage,
                CertificateStatusRequestExtensionSerializer> {

    public CertificateStatusRequestExtensionSerializerTest() {
        super(
                CertificateStatusRequestExtensionMessage::new,
                CertificateStatusRequestExtensionSerializer::new,
                List.of(
                        (msg, obj) -> msg.setCertificateStatusRequestType((Integer) obj),
                        (msg, obj) -> msg.setResponderIDListLength((Integer) obj),
                        (msg, obj) -> msg.setResponderIDList((byte[]) obj),
                        (msg, obj) -> msg.setRequestExtensionLength((Integer) obj),
                        (msg, obj) -> msg.setRequestExtension((byte[]) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return CertificateStatusRequestExtensionParserTest.provideTestVectors();
    }
}
