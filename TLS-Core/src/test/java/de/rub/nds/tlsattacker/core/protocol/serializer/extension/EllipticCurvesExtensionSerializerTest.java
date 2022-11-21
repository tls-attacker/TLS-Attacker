/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.EllipticCurvesExtensionParserTest;
import org.junit.jupiter.params.provider.Arguments;

import java.util.List;
import java.util.stream.Stream;

public class EllipticCurvesExtensionSerializerTest
    extends AbstractExtensionMessageSerializerTest<EllipticCurvesExtensionMessage, EllipticCurvesExtensionSerializer> {

    public EllipticCurvesExtensionSerializerTest() {
        super(EllipticCurvesExtensionMessage::new, EllipticCurvesExtensionSerializer::new,
            List.of((msg, obj) -> msg.setSupportedGroupsLength((Integer) obj),
                (msg, obj) -> msg.setSupportedGroups((byte[]) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return EllipticCurvesExtensionParserTest.provideTestVectors();
    }
}
