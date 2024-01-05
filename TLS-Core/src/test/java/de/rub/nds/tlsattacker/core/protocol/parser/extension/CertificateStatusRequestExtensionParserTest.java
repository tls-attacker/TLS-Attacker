/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class CertificateStatusRequestExtensionParserTest
        extends AbstractExtensionParserTest<
                CertificateStatusRequestExtensionMessage, CertificateStatusRequestExtensionParser> {

    public CertificateStatusRequestExtensionParserTest() {
        super(
                CertificateStatusRequestExtensionMessage.class,
                (stream, context) ->
                        new CertificateStatusRequestExtensionParser(
                                stream, ProtocolVersion.TLS12, context),
                List.of(
                        Named.of(
                                "CertificateStatusRequestExtensionMessage::getCertificateStatusRequestType",
                                CertificateStatusRequestExtensionMessage
                                        ::getCertificateStatusRequestType),
                        Named.of(
                                "CertificateStatusRequestExtensionMessage::getResponderIDListLength",
                                CertificateStatusRequestExtensionMessage::getResponderIDListLength),
                        Named.of(
                                "CertificateStatusRequestExtensionMessage::getResponderIDList",
                                CertificateStatusRequestExtensionMessage::getResponderIDList),
                        Named.of(
                                "CertificateStatusRequestExtensionMessage::getRequestExtensionLength",
                                CertificateStatusRequestExtensionMessage
                                        ::getRequestExtensionLength),
                        Named.of(
                                "CertificateStatusRequestExtensionMessage::getRequestExtension",
                                CertificateStatusRequestExtensionMessage::getRequestExtension)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("000500050100000000"),
                        List.of(),
                        ExtensionType.STATUS_REQUEST,
                        5,
                        List.of(1, 0, new byte[0], 0, new byte[0])),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("0005000701000102000103"),
                        List.of(),
                        ExtensionType.STATUS_REQUEST,
                        7,
                        List.of(1, 1, new byte[] {0x02}, 1, new byte[] {0x03})));
    }
}
