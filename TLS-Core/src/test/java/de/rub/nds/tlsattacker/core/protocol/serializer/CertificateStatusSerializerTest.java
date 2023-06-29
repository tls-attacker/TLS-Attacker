/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.CertificateStatusMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateStatusParserTest;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class CertificateStatusSerializerTest
        extends AbstractHandshakeMessageSerializerTest<
                CertificateStatusMessage, CertificateStatusSerializer> {

    public CertificateStatusSerializerTest() {
        super(
                CertificateStatusMessage::new,
                CertificateStatusSerializer::new,
                List.of(
                        (msg, obj) -> msg.setCertificateStatusType((Integer) obj),
                        (msg, obj) -> msg.setOcspResponseLength((Integer) obj),
                        (msg, obj) -> msg.setOcspResponseBytes((byte[]) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return CertificateStatusParserTest.provideTestVectors();
    }
}
