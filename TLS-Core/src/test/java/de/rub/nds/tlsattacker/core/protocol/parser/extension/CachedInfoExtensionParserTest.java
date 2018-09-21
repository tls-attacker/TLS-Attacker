/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CachedInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.CachedObjectPreparator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class CachedInfoExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {
                { ExtensionType.CACHED_INFO, ConnectionEndType.SERVER, 2, new byte[] { 0x01, 0x02 },
                        Arrays.asList(new CachedObject((byte) 1, null, null), new CachedObject((byte) 2, null, null)),
                        ArrayConverter.hexStringToByteArray("0019000400020102"), 4 },
                {
                        ExtensionType.CACHED_INFO,
                        ConnectionEndType.CLIENT,
                        13,
                        ArrayConverter.hexStringToByteArray("01060102030405060203070809"),
                        Arrays.asList(
                                new CachedObject((byte) 1, 6, ArrayConverter.hexStringToByteArray("010203040506")),
                                new CachedObject((byte) 2, 3, new byte[] { 0x07, 0x08, 0x09 })),
                        ArrayConverter.hexStringToByteArray("0019000f000d01060102030405060203070809"), 15 } });
    }

    private final ExtensionType type;
    private final ConnectionEndType connectionEndType;
    private final int cachedInfoLength;
    private final byte[] cachedInfoBytes;
    private final List<CachedObject> cachedObjectList;
    private final byte[] extensionBytes;
    private final int extensionLength;

    public CachedInfoExtensionParserTest(ExtensionType type, ConnectionEndType connectionEndType, int cachedInfoLength,
            byte[] cachedInfoBytes, List<CachedObject> cachedObjectList, byte[] extensionBytes, int extensionLength) {
        this.type = type;
        this.connectionEndType = connectionEndType;
        this.cachedInfoLength = cachedInfoLength;
        this.cachedInfoBytes = cachedInfoBytes;
        this.cachedObjectList = cachedObjectList;
        this.extensionBytes = extensionBytes;
        this.extensionLength = extensionLength;
    }

    @Test
    public void testParse() {
        TlsContext context = new TlsContext();

        CachedInfoExtensionParser parser = new CachedInfoExtensionParser(0, extensionBytes);
        CachedInfoExtensionMessage msg = parser.parse();

        assertArrayEquals(type.getValue(), msg.getExtensionType().getValue());
        assertEquals(extensionLength, (long) msg.getExtensionLength().getValue());
        assertArrayEquals(cachedInfoBytes, msg.getCachedInfoBytes().getValue());
        assertEquals(cachedInfoLength, (long) msg.getCachedInfoLength().getValue());
        assertCachedObjectList(cachedObjectList, msg.getCachedInfo());
    }

    public void assertCachedObjectList(List<CachedObject> expected, List<CachedObject> actual) {
        for (int i = 0; i < expected.size(); i++) {
            CachedObject expectedObject = expected.get(i);
            CachedObject actualObject = actual.get(i);

            CachedObjectPreparator preparator = new CachedObjectPreparator(new TlsContext().getChooser(),
                    expectedObject);
            preparator.prepare();

            assertEquals(expectedObject.getCachedInformationType().getValue(), actualObject.getCachedInformationType()
                    .getValue());

            if (expectedObject.getHashValueLength() != null && expectedObject.getHashValueLength().getValue() != null) {
                assertEquals(expectedObject.getHashValueLength().getValue(), actualObject.getHashValueLength()
                        .getValue());
            } else {
                assertNull(actualObject.getHashValueLength());
            }
            if (expectedObject.getHashValue() != null && expectedObject.getHashValue().getValue() != null) {
                assertArrayEquals(expectedObject.getHashValue().getValue(), actualObject.getHashValue().getValue());
            } else {
                assertNull(actualObject.getHashValue());
            }
        }
    }
}
