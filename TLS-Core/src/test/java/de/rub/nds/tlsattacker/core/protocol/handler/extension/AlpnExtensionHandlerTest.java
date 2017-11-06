/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.AlpnExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.AlpnExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.AlpnExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class AlpnExtensionHandlerTest {

    private final byte[] announcedProtocols = ArrayConverter.hexStringToByteArray("02683208687474702f312e31");
    private final int announcedProtocolsLength = 12;
    private AlpnExtensionHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new AlpnExtensionHandler(context);
    }

    @Test
    public void testAdjustTLSContext() {
        AlpnExtensionMessage msg = new AlpnExtensionMessage();
        msg.setAlpnExtensionLength(announcedProtocolsLength);
        msg.setAlpnAnnouncedProtocols(announcedProtocols);

        handler.adjustTLSContext(msg);

        assertArrayEquals(announcedProtocols, context.getAlpnAnnouncedProtocols());
    }

    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[0], 0) instanceof AlpnExtensionParser);
    }

    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new AlpnExtensionMessage()) instanceof AlpnExtensionPreparator);
    }

    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new AlpnExtensionMessage()) instanceof AlpnExtensionSerializer);
    }
}
