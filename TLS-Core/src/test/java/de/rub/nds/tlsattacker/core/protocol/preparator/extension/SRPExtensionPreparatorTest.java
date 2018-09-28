/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.SRPExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SRPExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class SRPExtensionPreparatorTest {

    private TlsContext context;
    private SRPExtensionPreparator preparator;
    private SRPExtensionMessage message;
    private final byte[] srpIdentifier = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04 };
    private final int srpIdentifierLength = 5;

    @Before
    public void setUp() {
        context = new TlsContext();
        message = new SRPExtensionMessage();
        preparator = new SRPExtensionPreparator(context.getChooser(), message, new SRPExtensionSerializer(message));
    }

    @Test
    public void testPreparator() {
        context.getConfig().setSecureRemotePasswordExtensionIdentifier(srpIdentifier);

        preparator.prepare();

        assertArrayEquals(srpIdentifier, message.getSrpIdentifier().getValue());
        assertEquals(srpIdentifierLength, (long) message.getSrpIdentifierLength().getValue());

    }

}
