/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RecordSizeLimitExtensionMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class RecordSizeLimitExtensionParserTest
        extends AbstractExtensionParserTest<
                RecordSizeLimitExtensionMessage, RecordSizeLimitExtensionParser> {

    public RecordSizeLimitExtensionParserTest() {
        super(
                RecordSizeLimitExtensionMessage.class,
                RecordSizeLimitExtensionParser::new,
                List.of(
                        Named.of(
                                "RecordSizeLimitExtensionMessage::getRecordSizeLimit",
                                RecordSizeLimitExtensionMessage::getRecordSizeLimit)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        DataConverter.hexStringToByteArray("001C00022000"),
                        List.of(),
                        ExtensionType.RECORD_SIZE_LIMIT,
                        2,
                        List.of(DataConverter.hexStringToByteArray("2000"))));
    }
}
