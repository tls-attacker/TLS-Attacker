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
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.PWDServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class PWDServerKeyExchangeParserTest
        extends AbstractHandshakeMessageParserTest<
                PWDServerKeyExchangeMessage, PWDServerKeyExchangeParser> {

    public PWDServerKeyExchangeParserTest() {
        super(
                PWDServerKeyExchangeMessage.class,
                PWDServerKeyExchangeParser::new,
                List.of(
                        Named.of(
                                "PWDServerKeyExchangeMessage::getSaltLength",
                                PWDServerKeyExchangeMessage::getSaltLength),
                        Named.of(
                                "PWDServerKeyExchangeMessage::getSalt",
                                PWDServerKeyExchangeMessage::getSalt),
                        Named.of(
                                "PWDServerKeyExchangeMessage::getElementLength",
                                PWDServerKeyExchangeMessage::getElementLength),
                        Named.of(
                                "PWDServerKeyExchangeMessage::getElement",
                                PWDServerKeyExchangeMessage::getElement),
                        Named.of(
                                "PWDServerKeyExchangeMessage::getScalarLength",
                                PWDServerKeyExchangeMessage::getScalarLength),
                        Named.of(
                                "PWDServerKeyExchangeMessage::getScalar",
                                PWDServerKeyExchangeMessage::getScalar),
                        Named.of(
                                "PWDServerKeyExchangeMessage::getGroupType",
                                PWDServerKeyExchangeMessage::getGroupType),
                        Named.of(
                                "PWDServerKeyExchangeMessage::getNamedGroup",
                                PWDServerKeyExchangeMessage::getNamedGroup),
                        Named.of(
                                "ServerKeyExchangeMessage::getPublicKeyLength",
                                ServerKeyExchangeMessage::getPublicKeyLength),
                        Named.of(
                                "ServerKeyExchangeMessage::getPublicKey",
                                ServerKeyExchangeMessage::getPublicKey),
                        Named.of(
                                "ServerKeyExchangeMessage::getSignatureAndHashAlgorithm",
                                ServerKeyExchangeMessage::getSignatureAndHashAlgorithm),
                        Named.of(
                                "ServerKeyExchangeMessage::getSignatureLength",
                                ServerKeyExchangeMessage::getSignatureLength),
                        Named.of(
                                "ServerKeyExchangeMessage::getSignature",
                                ServerKeyExchangeMessage::getSignature)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        ArrayConverter.hexStringToByteArray(
                                "0c00008720963c77cdc13a2a8d75cdddd1e0449929843711c21d47ce6e6383cdda37e47da303001a410422bbd56b481d7fa90c35e8d42fcd06618a0778de506b1bc38882abc73132eef37f02e13bd544acc145bdd806450d43be34b9288348d03d6cd9832487b129dbe1202f704896699fc424d3cec33717644f5adf7f68483424ee51492bb96613fc4921"),
                        Arrays.asList(
                                HandshakeMessageType.SERVER_KEY_EXCHANGE.getValue(),
                                135,
                                32,
                                ArrayConverter.hexStringToByteArray(
                                        "963c77cdc13a2a8d75cdddd1e0449929843711c21d47ce6e6383cdda37e47da3"),
                                65,
                                ArrayConverter.hexStringToByteArray(
                                        "0422bbd56b481d7fa90c35e8d42fcd06618a0778de506b1bc38882abc73132eef37f02e13bd544acc145bdd806450d43be34b9288348d03d6cd9832487b129dbe1"),
                                32,
                                ArrayConverter.hexStringToByteArray(
                                        "2f704896699fc424d3cec33717644f5adf7f68483424ee51492bb96613fc4921"),
                                EllipticCurveType.NAMED_CURVE.getValue(),
                                NamedGroup.BRAINPOOLP256R1.getValue(),
                                null,
                                null,
                                null,
                                null,
                                null)));
    }
}
