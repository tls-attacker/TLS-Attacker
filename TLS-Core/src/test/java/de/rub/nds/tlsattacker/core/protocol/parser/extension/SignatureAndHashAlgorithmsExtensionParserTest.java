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
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class SignatureAndHashAlgorithmsExtensionParserTest
        extends AbstractExtensionParserTest<
                SignatureAndHashAlgorithmsExtensionMessage,
                SignatureAndHashAlgorithmsExtensionParser> {

    public SignatureAndHashAlgorithmsExtensionParserTest() {
        super(
                SignatureAndHashAlgorithmsExtensionMessage.class,
                SignatureAndHashAlgorithmsExtensionParser::new,
                List.of(
                        Named.of(
                                "SignatureAndHashAlgorithmsExtensionMessage::getSignatureAndHashAlgorithmsLength",
                                SignatureAndHashAlgorithmsExtensionMessage
                                        ::getSignatureAndHashAlgorithmsLength),
                        Named.of(
                                "SignatureAndHashAlgorithmsExtensionMessage::getSignatureAndHashAlgorithms",
                                SignatureAndHashAlgorithmsExtensionMessage
                                        ::getSignatureAndHashAlgorithms)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "000d0020001e060106020603050105020503040104020403030103020303020102020203"),
                        List.of(),
                        ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS,
                        32,
                        List.of(
                                30,
                                ArrayConverter.hexStringToByteArray(
                                        "060106020603050105020503040104020403030103020303020102020203"))));
    }
}
