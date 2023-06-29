/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
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
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

public class CachedInfoExtensionHandlerTest
        extends AbstractExtensionMessageHandlerTest<
                CachedInfoExtensionMessage, CachedInfoExtensionHandler> {

    private final List<CachedObject> cachedObjects =
            Arrays.asList(
                    new CachedObject((byte) 1, 2, new byte[] {0x01, 0x02}),
                    new CachedObject((byte) 2, 3, new byte[] {0x01, 0x02, 0x03}));

    public CachedInfoExtensionHandlerTest() {
        super(CachedInfoExtensionMessage::new, CachedInfoExtensionHandler::new);
    }

    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        CachedInfoExtensionMessage msg = new CachedInfoExtensionMessage();
        msg.setCachedInfo(cachedObjects);
        CachedInfoExtensionPreparator preparator =
                new CachedInfoExtensionPreparator(context.getChooser(), msg);
        preparator.prepare();

        handler.adjustContext(msg);

        assertCachedObjectList(cachedObjects, context.getCachedInfoExtensionObjects());
    }

    public void assertCachedObjectList(List<CachedObject> expected, List<CachedObject> actual) {
        for (int i = 0; i < expected.size(); i++) {
            CachedObject expectedObject = expected.get(i);
            CachedObject actualObject = actual.get(i);

            assertEquals(
                    expectedObject.getCachedInformationType().getValue(),
                    actualObject.getCachedInformationType().getValue());
            assertEquals(
                    expectedObject.getHashValueLength().getValue(),
                    actualObject.getHashValueLength().getValue());
            assertArrayEquals(
                    expectedObject.getHashValue().getValue(),
                    actualObject.getHashValue().getValue());
        }
    }
}
