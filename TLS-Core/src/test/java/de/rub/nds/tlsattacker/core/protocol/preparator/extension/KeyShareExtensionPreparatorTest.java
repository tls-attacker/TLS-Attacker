/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KS.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.KeyShareExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class KeyShareExtensionPreparatorTest {

    private KeyShareExtensionPreparator preparator;
    private KeyShareExtensionMessage message;
    private TlsContext context;

    public KeyShareExtensionPreparatorTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        message = new KeyShareExtensionMessage(ExtensionType.KEY_SHARE);
        preparator = new KeyShareExtensionPreparator(context.getChooser(), message, new KeyShareExtensionSerializer(
                message, ConnectionEndType.CLIENT));
    }

    /**
     * Test of prepare method, of class KeyShareExtensionPreparator.
     */
    @Test
    public void testPrepare() {
        List<KeyShareEntry> keyShareList = new LinkedList<>();
        KeyShareEntry entry = new KeyShareEntry(NamedGroup.ECDH_X25519, new BigInteger(
                "03BD8BCA70C19F657E897E366DBE21A466E4924AF6082DBDF573827BCDDE5DEF", 16));
        keyShareList.add(entry);
        message.setKeyShareList(keyShareList);
        preparator.prepare();
        assertArrayEquals(
                message.getKeyShareListBytes().getValue(),
                ArrayConverter
                        .hexStringToByteArray("001D00202a981db6cdd02a06c1763102c9e741365ac4e6f72b3176a6bd6a3523d3ec0f4c"));
        assertTrue(message.getKeyShareListLength().getValue() == 36);
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }

}
