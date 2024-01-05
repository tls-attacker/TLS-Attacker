/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateRequestParserTest;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class CertificateRequestSerializerTest
        extends AbstractHandshakeMessageSerializerTest<
                CertificateRequestMessage, CertificateRequestSerializer> {

    public CertificateRequestSerializerTest() {
        super(
                CertificateRequestMessage::new,
                CertificateRequestSerializer::new,
                List.of(
                        (msg, obj) -> msg.setClientCertificateTypesCount((Integer) obj),
                        (msg, obj) -> msg.setClientCertificateTypes((byte[]) obj),
                        (msg, obj) -> msg.setSignatureHashAlgorithmsLength((Integer) obj),
                        (msg, obj) -> msg.setSignatureHashAlgorithms((byte[]) obj),
                        (msg, obj) -> msg.setDistinguishedNamesLength((Integer) obj),
                        (msg, obj) -> msg.setDistinguishedNames((byte[]) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return CertificateRequestParserTest.provideTestVectors();
    }
}
