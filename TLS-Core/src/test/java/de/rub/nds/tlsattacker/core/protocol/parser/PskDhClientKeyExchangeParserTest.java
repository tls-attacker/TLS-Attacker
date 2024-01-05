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
import de.rub.nds.tlsattacker.core.protocol.message.PskDhClientKeyExchangeMessage;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class PskDhClientKeyExchangeParserTest
        extends AbstractHandshakeMessageParserTest<
                PskDhClientKeyExchangeMessage, PskDhClientKeyExchangeParser> {

    public PskDhClientKeyExchangeParserTest() {
        super(
                PskDhClientKeyExchangeMessage.class,
                PskDhClientKeyExchangeParser::new,
                List.of(
                        Named.of(
                                "PskDhClientKeyExchangeMessage::getIdentityLength",
                                PskDhClientKeyExchangeMessage::getIdentityLength),
                        Named.of(
                                "PskDhClientKeyExchangeMessage::getIdentity",
                                PskDhClientKeyExchangeMessage::getIdentity),
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
                                "10000093000f436c69656e745f6964656e74697479008032d08c13c3c7ef291e4bc7854eed91ddef2737260c09573aa8def5ce79e964a5598797470501ee6ff8be72cd8c3bbaf46ab55b77851029db3cfb38a12040a15bc8512dba290d9cae345ecf24f347e1c80c65b230e265e13c8a571e0842539536d062a6141de09017d27ac2d64c0d29cbaa19d5e55c3c6c5035c87788ac776177"),
                        List.of(
                                HandshakeMessageType.CLIENT_KEY_EXCHANGE.getValue(),
                                147,
                                15,
                                ("Client_identity".getBytes(StandardCharsets.UTF_8)),
                                128,
                                ArrayConverter.hexStringToByteArray(
                                        "32d08c13c3c7ef291e4bc7854eed91ddef2737260c09573aa8def5ce79e964a5598797470501ee6ff8be72cd8c3bbaf46ab55b77851029db3cfb38a12040a15bc8512dba290d9cae345ecf24f347e1c80c65b230e265e13c8a571e0842539536d062a6141de09017d27ac2d64c0d29cbaa19d5e55c3c6c5035c87788ac776177"))));
    }
}
