/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.RenegotiationInfoExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.RenegotiationInfoExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.RenegotiationInfoExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class RenegotiationInfoExtensionHandlerTest {

    private static final int EXTENSION_LENGTH = 1;
    private static final byte[] EXTENSION_INFO = new byte[] { 0 };
    private TlsContext context;
    private RenegotiationInfoExtensionHandler handler;

    @Before
    public void setUp() {
        context = new TlsContext();
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        handler = new RenegotiationInfoExtensionHandler(context);
    }

    @Test
    public void testAdjustTLSContext() {
        RenegotiationInfoExtensionMessage message = new RenegotiationInfoExtensionMessage();
        message.setRenegotiationInfo(EXTENSION_INFO);
        message.setExtensionLength(EXTENSION_LENGTH);
        handler.adjustTLSContext(message);
        assertArrayEquals(context.getRenegotiationInfo(), EXTENSION_INFO);
    }

    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[0], 0) instanceof RenegotiationInfoExtensionParser);
    }

    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new RenegotiationInfoExtensionMessage()) instanceof RenegotiationInfoExtensionPreparator);
    }

    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new RenegotiationInfoExtensionMessage()) instanceof RenegotiationInfoExtensionSerializer);
    }

}
