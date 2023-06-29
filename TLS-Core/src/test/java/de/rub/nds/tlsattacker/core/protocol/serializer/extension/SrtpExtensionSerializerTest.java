/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.SrtpExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SrtpExtensionParserTest;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class SrtpExtensionSerializerTest
        extends AbstractExtensionMessageSerializerTest<
                SrtpExtensionMessage, SrtpExtensionSerializer> {

    public SrtpExtensionSerializerTest() {
        super(
                SrtpExtensionMessage::new,
                SrtpExtensionSerializer::new,
                List.of(
                        (msg, obj) -> msg.setSrtpProtectionProfilesLength((Integer) obj),
                        (msg, obj) -> msg.setSrtpProtectionProfiles((byte[]) obj),
                        (msg, obj) -> msg.setSrtpMkiLength((Integer) obj),
                        (msg, obj) -> msg.setSrtpMki((byte[]) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return SrtpExtensionParserTest.provideTestVectors();
    }
}
