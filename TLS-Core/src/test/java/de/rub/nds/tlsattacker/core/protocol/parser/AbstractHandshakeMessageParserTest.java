/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.unittest.helper.QuadFunction;
import org.junit.jupiter.api.Named;

import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

abstract class AbstractHandshakeMessageParserTest<MT extends HandshakeMessage, PT extends HandshakeMessageParser<MT>>
    extends AbstractTlsMessageParserTest<MT, PT> {

    AbstractHandshakeMessageParserTest(QuadFunction<Integer, byte[], ProtocolVersion, Config, PT> parserConstructor) {
        this(parserConstructor, List.of());
    }

    AbstractHandshakeMessageParserTest(QuadFunction<Integer, byte[], ProtocolVersion, Config, PT> parserConstructor,
        List<Named<Function<MT, Object>>> messageGetters) {
        super(parserConstructor, addHandshakeMessageGetters(messageGetters));
    }

    private static <MT extends HandshakeMessage> List<Named<Function<MT, Object>>>
        addHandshakeMessageGetters(List<Named<Function<MT, Object>>> messageGetters) {
        return Stream
            .concat(
                Stream.of(
                    Named.of("HandshakeMessage::getHandshakeMessageType",
                        (Function<MT, Object>) HandshakeMessage::getType),
                    Named.of("HandshakeMessage::getLength", (Function<MT, Object>) HandshakeMessage::getLength)),
                messageGetters.stream())
            .collect(Collectors.toUnmodifiableList());
    }
}
