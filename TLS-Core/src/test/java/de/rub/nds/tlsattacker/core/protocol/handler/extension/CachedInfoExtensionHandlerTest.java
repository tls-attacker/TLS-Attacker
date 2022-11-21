/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.protocol.message.extension.CachedInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.CachedInfoExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.CachedInfoExtensionSerializer;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

public class CachedInfoExtensionHandlerTest
    extends AbstractExtensionMessageHandlerTest<CachedInfoExtensionMessage, CachedInfoExtensionHandler> {

    private final List<CachedObject> cachedObjects =
        Arrays.asList(new CachedObject((byte) 1, 2, new byte[] { 0x01, 0x02 }),
            new CachedObject((byte) 2, 3, new byte[] { 0x01, 0x02, 0x03 }));

    public CachedInfoExtensionHandlerTest() {
        super(CachedInfoExtensionMessage::new, CachedInfoExtensionHandler::new);
    }

    @Test
    @Override
    public void testAdjustTLSContext() {
        CachedInfoExtensionMessage msg = new CachedInfoExtensionMessage();
        msg.setCachedInfo(cachedObjects);
        CachedInfoExtensionPreparator preparator =
            new CachedInfoExtensionPreparator(context.getChooser(), msg, new CachedInfoExtensionSerializer(msg));
        preparator.prepare();

        handler.adjustTLSContext(msg);

        assertCachedObjectList(cachedObjects, context.getCachedInfoExtensionObjects());
    }

    public void assertCachedObjectList(List<CachedObject> expected, List<CachedObject> actual) {
        for (int i = 0; i < expected.size(); i++) {
            CachedObject expectedObject = expected.get(i);
            CachedObject actualObject = actual.get(i);

            assertEquals(expectedObject.getCachedInformationType().getValue(),
                actualObject.getCachedInformationType().getValue());
            assertEquals(expectedObject.getHashValueLength().getValue(), actualObject.getHashValueLength().getValue());
            assertArrayEquals(expectedObject.getHashValue().getValue(), actualObject.getHashValue().getValue());
        }
    }
}
