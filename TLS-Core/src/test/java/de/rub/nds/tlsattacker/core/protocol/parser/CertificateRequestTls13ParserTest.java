/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class CertificateRequestTls13ParserTest
        extends AbstractHandshakeMessageParserTest<
                CertificateRequestMessage, CertificateRequestParser> {

    public CertificateRequestTls13ParserTest() {
        super(
                CertificateRequestMessage.class,
                CertificateRequestParser::new,
                List.of(
                        Named.of(
                                "CertificateRequestMessage::getCertificateRequestContextLength",
                                CertificateRequestMessage::getCertificateRequestContextLength),
                        Named.of(
                                "CertificateRequestMessage::getCertificateRequestContext",
                                CertificateRequestMessage::getCertificateRequestContext),
                        Named.of(
                                "CertificateRequestMessage::getExtensionsLength",
                                CertificateRequestMessage::getExtensionsLength),
                        Named.of(
                                "CertificateRequestMessage::getExtensionBytes",
                                CertificateRequestMessage::getExtensionBytes)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ProtocolVersion.TLS13,
                        ArrayConverter.hexStringToByteArray("0d00000401020000"),
                        List.of(
                                HandshakeMessageType.CERTIFICATE_REQUEST.getValue(),
                                4,
                                1,
                                ArrayConverter.hexStringToByteArray("02"),
                                0,
                                new byte[0])));
    }
}
