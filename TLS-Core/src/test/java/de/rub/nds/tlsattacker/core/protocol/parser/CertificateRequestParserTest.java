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
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class CertificateRequestParserTest
        extends AbstractHandshakeMessageParserTest<
                CertificateRequestMessage, CertificateRequestParser> {

    public CertificateRequestParserTest() {
        super(
                CertificateRequestMessage.class,
                CertificateRequestParser::new,
                List.of(
                        Named.of(
                                "CertificateRequestMessage::getClientCertificateTypesCount",
                                CertificateRequestMessage::getClientCertificateTypesCount),
                        Named.of(
                                "CertificateRequestMessage::getClientCertificateTypes",
                                CertificateRequestMessage::getClientCertificateTypes),
                        Named.of(
                                "CertificateRequestMessage::getSignatureHashAlgorithmsLength",
                                CertificateRequestMessage::getSignatureHashAlgorithmsLength),
                        Named.of(
                                "CertificateRequestMessage::getSignatureHashAlgorithms",
                                CertificateRequestMessage::getSignatureHashAlgorithms),
                        Named.of(
                                "CertificateRequestMessage::getDistinguishedNamesLength",
                                CertificateRequestMessage::getDistinguishedNamesLength),
                        Named.of(
                                "CertificateRequestMessage::getDistinguishedNames",
                                CertificateRequestMessage::getDistinguishedNames)));
    }

    private static final byte[] RSA_DSS_ECDSA_TYPES = ArrayConverter.hexStringToByteArray("010240");

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        ArrayConverter.hexStringToByteArray(
                                "0d00002603010240001e0601060206030501050205030401040204030301030203030201020202030000"),
                        Arrays.asList(
                                HandshakeMessageType.CERTIFICATE_REQUEST.getValue(),
                                38,
                                3,
                                RSA_DSS_ECDSA_TYPES,
                                30,
                                ArrayConverter.hexStringToByteArray(
                                        "060106020603050105020503040104020403030103020303020102020203"),
                                0,
                                null)));
    }
}
