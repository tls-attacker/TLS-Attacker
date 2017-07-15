/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.CachedInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.util.Arrays;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class CachedInfoExtensionPreparatorTest {
    private TlsContext context;
    private CachedInfoExtensionMessage msg;
    private CachedInfoExtensionPreparator preparator;
    private final List<CachedObject> cachedObjectsClient = Arrays.asList(new CachedObject(true, (byte) 0x01, 2,
            new byte[] { 0x01, 0x02 }));
    private final List<CachedObject> cachedObjectsServer = Arrays.asList(new CachedObject(false, (byte) 0x02, 0,
            new byte[] {}));
    private final int cachedObjectClientLength = 4;
    private final int cachedObjectServerLength = 1;

    @Before
    public void setUp() {
        context = new TlsContext();
        msg = new CachedInfoExtensionMessage();
        preparator = new CachedInfoExtensionPreparator(context, msg);
    }

    @Test
    public void testPreparator() {
        context.getConfig().setCachedObjectList(cachedObjectsClient);
        context.getConfig().setCachedInfoExtensionIsClientState(true);

        preparator.prepare();

        assertEquals(cachedObjectClientLength, (int) msg.getCachedInfoLength().getValue());
        assertCachedObjectList(cachedObjectsClient, msg.getCachedInfo());

        context.getConfig().setCachedObjectList(cachedObjectsServer);
        context.getConfig().setCachedInfoExtensionIsClientState(false);

        preparator.prepare();

        assertEquals(cachedObjectServerLength, (int) msg.getCachedInfoLength().getValue());
        assertCachedObjectList(cachedObjectsServer, msg.getCachedInfo());

    }

    public void assertCachedObjectList(List<CachedObject> expected, List<CachedObject> actual) {
        for (int i = 0; i < expected.size(); i++) {
            CachedObject expectedObject = expected.get(i);
            CachedObject actualObject = actual.get(i);

            assertEquals(expectedObject.getIsClientState().getValue(), actualObject.getIsClientState().getValue());
            assertEquals(expectedObject.getCachedInformationType().getValue(), actualObject.getCachedInformationType()
                    .getValue());
            assertEquals(expectedObject.getHashValueLength().getValue(), actualObject.getHashValueLength().getValue());
            assertArrayEquals(expectedObject.getHashValue().getValue(), actualObject.getHashValue().getValue());
        }
    }
}
