/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.protocol.message.extension.CachedInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.CachedInfoExtensionSerializer;
import java.util.List;
import org.junit.jupiter.api.Test;

public class CachedInfoExtensionPreparatorTest
        extends AbstractExtensionMessagePreparatorTest<
                CachedInfoExtensionMessage,
                CachedInfoExtensionSerializer,
                CachedInfoExtensionPreparator> {

    public CachedInfoExtensionPreparatorTest() {
        super(
                CachedInfoExtensionMessage::new,
                CachedInfoExtensionSerializer::new,
                CachedInfoExtensionPreparator::new);
    }

    @Test
    @Override
    public void testPrepare() {
        List<CachedObject> cachedObjectsClient =
                List.of(new CachedObject((byte) 1, 2, new byte[] {0x01, 0x02}));
        List<CachedObject> cachedObjectsServer = List.of(new CachedObject((byte) 0x02, null, null));

        message.setCachedInfo(cachedObjectsClient);
        preparator.prepare();
        assertEquals(4, message.getCachedInfoLength().getValue());
        assertCachedObjectList(cachedObjectsClient, message.getCachedInfo());
        message.setCachedInfo(cachedObjectsServer);
        preparator.prepare();
        assertEquals(1, message.getCachedInfoLength().getValue());
        assertCachedObjectList(cachedObjectsServer, message.getCachedInfo());
    }

    public void assertCachedObjectList(List<CachedObject> expected, List<CachedObject> actual) {
        for (int i = 0; i < expected.size(); i++) {
            CachedObject expectedObject = expected.get(i);
            CachedObject actualObject = actual.get(i);

            assertEquals(
                    expectedObject.getCachedInformationType().getValue(),
                    actualObject.getCachedInformationType().getValue());
            if (expectedObject.getHashValueLength() != null
                    && expectedObject.getHashValueLength().getValue() != null) {
                assertEquals(
                        expectedObject.getHashValueLength().getValue(),
                        actualObject.getHashValueLength().getValue());
            } else {
                assertNull(actualObject.getHashValueLength());
            }
            if (expectedObject.getHashValue() != null
                    && expectedObject.getHashValue().getValue() != null) {
                assertArrayEquals(
                        expectedObject.getHashValue().getValue(),
                        actualObject.getHashValue().getValue());
            } else {
                assertNull(actualObject.getHashValue());
            }
        }
    }
}
