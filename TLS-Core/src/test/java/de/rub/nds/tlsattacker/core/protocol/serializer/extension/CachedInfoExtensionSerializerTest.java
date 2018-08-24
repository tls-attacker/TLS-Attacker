/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CachedInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.CachedInfoExtensionParserTest;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.CachedInfoExtensionPreparator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.Collection;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class CachedInfoExtensionSerializerTest {
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return CachedInfoExtensionParserTest.generateData();
    }

    private final ExtensionType type;
    private final ConnectionEndType isClientState;
    private final int cachedInfoLength;
    private final byte[] cachedInfoBytes;
    private final List<CachedObject> cachedObjectList;
    private final byte[] extensionBytes;
    private final int extensionLength;
    private CachedInfoExtensionSerializer serializer;
    private CachedInfoExtensionMessage msg;

    public CachedInfoExtensionSerializerTest(ExtensionType type, ConnectionEndType isClientState, int cachedInfoLength,
            byte[] cachedInfoBytes, List<CachedObject> cachedObjectList, byte[] extensionBytes, int extensionLength) {
        this.type = type;
        this.isClientState = isClientState;
        this.cachedInfoLength = cachedInfoLength;
        this.cachedInfoBytes = cachedInfoBytes;
        this.cachedObjectList = cachedObjectList;
        this.extensionBytes = extensionBytes;
        this.extensionLength = extensionLength;
    }

    @Before
    public void setUp() {
        msg = new CachedInfoExtensionMessage();
        serializer = new CachedInfoExtensionSerializer(msg);
    }

    @Test
    public void testSerializeExtensionContent() {
        msg.setCachedInfo(cachedObjectList);
        msg.setExtensionType(type.getValue());
        msg.setExtensionLength(extensionLength);
        msg.setCachedInfoLength(cachedInfoLength);

        CachedInfoExtensionPreparator preparator = new CachedInfoExtensionPreparator(new TlsContext().getChooser(),
                msg, new CachedInfoExtensionSerializer(msg));
        preparator.prepare();

        assertArrayEquals(extensionBytes, serializer.serialize());
    }
}
