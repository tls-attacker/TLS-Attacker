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
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskEcDhClientKeyExchangeMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class PskEcDhClientKeyExchangeParserTest
        extends AbstractHandshakeMessageParserTest<
                PskEcDhClientKeyExchangeMessage, PskEcDhClientKeyExchangeParser> {

    public PskEcDhClientKeyExchangeParserTest() {
        super(
                PskEcDhClientKeyExchangeMessage.class,
                PskEcDhClientKeyExchangeParser::new,
                List.of(
                        Named.of(
                                "PskEcDhClientKeyExchangeMessage::getIdentityLength",
                                PskEcDhClientKeyExchangeMessage::getIdentityLength),
                        Named.of(
                                "PskEcDhClientKeyExchangeMessage::getIdentity",
                                PskEcDhClientKeyExchangeMessage::getIdentity),
                        Named.of(
                                "ClientKeyExchangeMessage::getPublicKeyLength",
                                ClientKeyExchangeMessage::getPublicKeyLength),
                        Named.of(
                                "ClientKeyExchangeMessage::getPublicKey",
                                ClientKeyExchangeMessage::getPublicKey)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        ArrayConverter.hexStringToByteArray(
                                "10000032000f436c69656e745f6964656e7469747920f73171f4379e1897f443a82bcc06d79368f96aad699f10d21505c661fe80655b"),
                        List.of(
                                HandshakeMessageType.CLIENT_KEY_EXCHANGE.getValue(),
                                50,
                                15,
                                ArrayConverter.hexStringToByteArray(
                                        "436c69656e745f6964656e74697479"),
                                32,
                                ArrayConverter.hexStringToByteArray(
                                        "f73171f4379e1897f443a82bcc06d79368f96aad699f10d21505c661fe80655b"))),
                Arguments.of(
                        ProtocolVersion.TLS12,
                        ArrayConverter.hexStringToByteArray(
                                "10000032000f436c69656e745f6964656e746974792073f7cf3676cef0cf08b800519732540c8a16062aa5e24fc2360007c265b83f1b"),
                        List.of(
                                HandshakeMessageType.CLIENT_KEY_EXCHANGE.getValue(),
                                50,
                                15,
                                ArrayConverter.hexStringToByteArray(
                                        "436c69656e745f6964656e74697479"),
                                32,
                                ArrayConverter.hexStringToByteArray(
                                        "73f7cf3676cef0cf08b800519732540c8a16062aa5e24fc2360007c265b83f1b"))));
    }
}
