/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CachedInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.CachedObjectPreparator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class CachedInfoExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {
            { ConnectionEndType.SERVER, 2, new byte[] { 0x01, 0x02 },
                Arrays.asList(new CachedObject((byte) 1, null, null), new CachedObject((byte) 2, null, null)),
                ArrayConverter.hexStringToByteArray("00020102") },
            { ConnectionEndType.CLIENT, 13, ArrayConverter.hexStringToByteArray("01060102030405060203070809"),
                Arrays.asList(new CachedObject((byte) 1, 6, ArrayConverter.hexStringToByteArray("010203040506")),
                    new CachedObject((byte) 2, 3, new byte[] { 0x07, 0x08, 0x09 })),
                ArrayConverter.hexStringToByteArray("000d01060102030405060203070809") } });
    }

    private final int cachedInfoLength;
    private final byte[] cachedInfoBytes;
    private final List<CachedObject> cachedObjectList;
    private final byte[] extensionBytes;
    private final Config config = Config.createConfig();
    private final ConnectionEndType talkingConnectionEndType;

    public CachedInfoExtensionParserTest(ConnectionEndType talkingConnectionEndType, int cachedInfoLength,
        byte[] cachedInfoBytes, List<CachedObject> cachedObjectList, byte[] extensionBytes) {
        this.cachedInfoLength = cachedInfoLength;
        this.cachedInfoBytes = cachedInfoBytes;
        this.cachedObjectList = cachedObjectList;
        this.extensionBytes = extensionBytes;
        this.talkingConnectionEndType = talkingConnectionEndType;
    }

    @Test
    public void testParse() {
        TlsContext tlsContext = new TlsContext(config);
        tlsContext.setTalkingConnectionEndType(talkingConnectionEndType);

        CachedInfoExtensionParser parser =
            new CachedInfoExtensionParser(new ByteArrayInputStream(extensionBytes), tlsContext);
        CachedInfoExtensionMessage msg = new CachedInfoExtensionMessage();
        parser.parse(msg);

        assertArrayEquals(cachedInfoBytes, msg.getCachedInfoBytes().getValue());
        assertEquals(cachedInfoLength, (long) msg.getCachedInfoLength().getValue());
        assertCachedObjectList(cachedObjectList, msg.getCachedInfo());
    }

    public void assertCachedObjectList(List<CachedObject> expected, List<CachedObject> actual) {
        for (int i = 0; i < expected.size(); i++) {
            CachedObject expectedObject = expected.get(i);
            CachedObject actualObject = actual.get(i);

            CachedObjectPreparator preparator =
                new CachedObjectPreparator(new TlsContext().getChooser(), expectedObject);
            preparator.prepare();

            assertEquals(expectedObject.getCachedInformationType().getValue(),
                actualObject.getCachedInformationType().getValue());

            if (expectedObject.getHashValueLength() != null && expectedObject.getHashValueLength().getValue() != null) {
                assertEquals(expectedObject.getHashValueLength().getValue(),
                    actualObject.getHashValueLength().getValue());
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
