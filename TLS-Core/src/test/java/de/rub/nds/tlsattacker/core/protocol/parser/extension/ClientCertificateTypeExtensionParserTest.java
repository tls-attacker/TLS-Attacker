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
import de.rub.nds.tlsattacker.core.constants.CertificateType;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class ClientCertificateTypeExtensionParserTest
        extends AbstractExtensionParserTest<
                ClientCertificateTypeExtensionMessage, ClientCertificateTypeExtensionParser> {

    public ClientCertificateTypeExtensionParserTest() {
        super(
                ClientCertificateTypeExtensionMessage.class,
                ClientCertificateTypeExtensionParser::new,
                List.of(
                        Named.of(
                                "ClientCertificateTypeExtensionMessage::getCertificateTypesLength",
                                ClientCertificateTypeExtensionMessage::getCertificateTypesLength),
                        Named.of(
                                "ClientCertificateTypeExtensionMessage::getCertificateTypes",
                                ClientCertificateTypeExtensionMessage::getCertificateTypes)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("0013000100"),
                        List.of(ConnectionEndType.SERVER),
                        ExtensionType.CLIENT_CERTIFICATE_TYPE,
                        1,
                        Arrays.asList(
                                null,
                                CertificateType.toByteArray(List.of(CertificateType.X509)),
                                false)),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("001300020100"),
                        List.of(ConnectionEndType.CLIENT),
                        ExtensionType.CLIENT_CERTIFICATE_TYPE,
                        2,
                        Arrays.asList(
                                1,
                                CertificateType.toByteArray(List.of(CertificateType.X509)),
                                true)),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("00130003020100"),
                        List.of(ConnectionEndType.CLIENT),
                        ExtensionType.CLIENT_CERTIFICATE_TYPE,
                        3,
                        Arrays.asList(
                                2,
                                CertificateType.toByteArray(
                                        List.of(CertificateType.OPEN_PGP, CertificateType.X509)),
                                true)));
    }
}
