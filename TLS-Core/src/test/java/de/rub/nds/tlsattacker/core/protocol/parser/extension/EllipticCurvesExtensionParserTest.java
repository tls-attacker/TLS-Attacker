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
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class EllipticCurvesExtensionParserTest
        extends AbstractExtensionParserTest<
                EllipticCurvesExtensionMessage, EllipticCurvesExtensionParser> {

    public EllipticCurvesExtensionParserTest() {
        super(
                EllipticCurvesExtensionMessage.class,
                EllipticCurvesExtensionParser::new,
                List.of(
                        Named.of(
                                "EllipticCurvesExtensionMessage::getSupportedGroupsLength",
                                EllipticCurvesExtensionMessage::getSupportedGroupsLength),
                        Named.of(
                                "EllipticCurvesExtensionMessage::getSupportedGroups",
                                EllipticCurvesExtensionMessage::getSupportedGroups)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "000a001c001a00170019001c001b0018001a0016000e000d000b000c0009000a"),
                        List.of(),
                        ExtensionType.ELLIPTIC_CURVES,
                        28,
                        List.of(
                                26,
                                ArrayConverter.hexStringToByteArray(
                                        "00170019001c001b0018001a0016000e000d000b000c0009000a"))));
    }
}
