/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedRandomExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtendedRandomExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class ExtendedRandomExtensionPreparatorTest {

    private final int extensionLength = 0;
    private final byte[] extendedRandom = new byte[0];
    private TlsContext context;
    private ExtendedRandomExtensionMessage message;
    private ExtendedRandomExtensionPreparator preparator;

    @Before
    public void setUp() {
        context = new TlsContext();
        message = new ExtendedRandomExtensionMessage();
        preparator = new ExtendedRandomExtensionPreparator(context.getChooser(), message,
                new ExtendedRandomExtensionSerializer(message));
    }

    @Test
    public void testPreparator() {
        context.getConfig().setAddExtendedRandomExtension(true);
        context.getConfig().setDefaultClientExtendedRandom(extendedRandom);
        context.getConfig().setDefaultServerExtendedRandom(extendedRandom);
        preparator.prepare();

        assertArrayEquals(ExtensionType.EXTENDED_RANDOM.getValue(), message.getExtensionType().getValue());
        assertEquals(extensionLength, (long) message.getExtensionLength().getValue());
        assertArrayEquals(extendedRandom, message.getExtendedRandom().getValue());
    }

    @Test
    public void testGenerateSameLengthExtendedRandom() {
        context.getConfig().setAddExtendedRandomExtension(true);
        context.getConfig().setDefaultClientExtendedRandom(extendedRandom);
        InboundConnection serverConnection = new InboundConnection();
        context.setConnection(serverConnection);
        preparator.prepare();

        assertArrayEquals(ExtensionType.EXTENDED_RANDOM.getValue(), message.getExtensionType().getValue());
        assertEquals(extensionLength, (long) message.getExtensionLength().getValue());
        assertEquals(extendedRandom.length, message.getExtendedRandom().getValue().length);
        assertEquals(extendedRandom.length, context.getChooser().getServerExtendedRandom().length);
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }
}
