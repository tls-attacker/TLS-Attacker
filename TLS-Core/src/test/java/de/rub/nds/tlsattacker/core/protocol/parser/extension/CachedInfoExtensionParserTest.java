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
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
@RunWith(Parameterized.class)
public class CachedInfoExtensionParserTest {

    private final ExtensionType type;
    private final boolean isClientState;
    private final int cachedInfoLength;
    private final byte[] cachedInfoBytes;
    private final List<CachedObject> cachedObjectList;
    private final byte[] extensionBytes;
    private final int extensionLength;

    public CachedInfoExtensionParserTest(ExtensionType type, boolean isClientState, int cachedInfoLength,
            byte[] cachedInfoBytes, List<CachedObject> cachedObjectList, byte[] extensionBytes, int extensionLength) {
        this.type = type;
        this.isClientState = isClientState;
        this.cachedInfoLength = cachedInfoLength;
        this.cachedInfoBytes = cachedInfoBytes;
        this.cachedObjectList = cachedObjectList;
        this.extensionBytes = extensionBytes;
        this.extensionLength = extensionLength;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] {
                        {
                                ExtensionType.CACHED_INFO,
                                false,
                                2,
                                new byte[] { 0x01, 0x02 },
                                Arrays.asList(new CachedObject(false, (byte) 1, 0, new byte[] {}), new CachedObject(
                                        false, (byte) 2, 0, new byte[] {})),
                                ArrayConverter.hexStringToByteArray("0019000400020102"), 4 },
                        {
                                ExtensionType.CACHED_INFO,
                                true,
                                13,
                                ArrayConverter.hexStringToByteArray("01060102030405060203070809"),
                                Arrays.asList(
                                        new CachedObject(true, (byte) 1, 6, ArrayConverter
                                                .hexStringToByteArray("010203040506")), new CachedObject(true,
                                                (byte) 2, 3, new byte[] { 0x07, 0x08, 0x09 })),
                                ArrayConverter.hexStringToByteArray("0019000f000d01060102030405060203070809"), 15 } });
    }

    @Test
    public void testParse() {
        CachedInfoExtensionParser parser = new CachedInfoExtensionParser(0, extensionBytes);
        CachedInfoExtensionMessage msg = parser.parse();

        assertArrayEquals(type.getValue(), msg.getExtensionType().getValue());
        assertEquals(extensionLength, (int) msg.getExtensionLength().getValue());
        assertArrayEquals(cachedInfoBytes, msg.getCachedInfoBytes().getValue());
        assertEquals(isClientState, msg.getIsClientState().getValue());
        assertEquals(cachedInfoLength, (int) msg.getCachedInfoLength().getValue());
        assertCachedObjectList(cachedObjectList, msg.getCachedInfo());
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
