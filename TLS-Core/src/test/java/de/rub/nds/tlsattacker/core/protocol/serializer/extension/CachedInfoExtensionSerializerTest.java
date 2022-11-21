/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.CachedInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.CachedInfoExtensionParserTest;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.CachedInfoExtensionPreparator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.jupiter.params.provider.Arguments;

import java.util.List;
import java.util.stream.Stream;

public class CachedInfoExtensionSerializerTest
    extends AbstractExtensionMessageSerializerTest<CachedInfoExtensionMessage, CachedInfoExtensionSerializer> {

    public CachedInfoExtensionSerializerTest() {
        // noinspection unchecked
        super(CachedInfoExtensionMessage::new, CachedInfoExtensionSerializer::new,
            List.of((msg, obj) -> msg.setCachedInfoLength((Integer) obj), (msg, obj) -> {
            }, (msg, obj) -> msg.setCachedInfo((List<CachedObject>) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return CachedInfoExtensionParserTest.provideTestVectors();
    }

    @Override
    protected void setExtensionMessageSpecific(List<Object> providedAdditionalValues,
        List<Object> providedMessageSpecificValues) {
        super.setExtensionMessageSpecific(providedAdditionalValues, providedMessageSpecificValues);

        CachedInfoExtensionPreparator preparator = new CachedInfoExtensionPreparator(new TlsContext().getChooser(),
            message, new CachedInfoExtensionSerializer(message));
        preparator.prepare();
    }
}
