/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedRandomExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtendedRandomExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtendedRandomExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtendedRandomExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.Before;
import org.junit.Test;

public class ExtendedRandomExtensionHandlerTest {
    private static final byte[] EXTENDED_RANDOM_CLIENT = ArrayConverter.hexStringToByteArray("ABBA1234567890CD");
    private static final byte[] EXTENDED_RANDOM_SERVER = ArrayConverter.hexStringToByteArray("CCCC1234567890CD");

    private TlsContext context;
    private ExtendedRandomExtensionHandler handler;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new ExtendedRandomExtensionHandler(context);
    }

    @Test
    public void testAdjustTLSContext() {
        byte[] concatClientRandom = ArrayConverter.concatenate(context.getClientRandom(), EXTENDED_RANDOM_CLIENT);
        byte[] concatServerRandom = ArrayConverter.concatenate(context.getServerRandom(), EXTENDED_RANDOM_SERVER);

        ExtendedRandomExtensionMessage message = new ExtendedRandomExtensionMessage();
        message.setExtendedRandom(EXTENDED_RANDOM_CLIENT);
        message.setExtendedRandomLength(EXTENDED_RANDOM_CLIENT.length);
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        handler.adjustTLSContext(message);

        assertArrayEquals(EXTENDED_RANDOM_CLIENT, context.getClientExtendedRandom());

        message = new ExtendedRandomExtensionMessage();
        message.setExtendedRandom(EXTENDED_RANDOM_SERVER);
        message.setExtendedRandomLength(EXTENDED_RANDOM_SERVER.length);
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        handler.adjustTLSContext(message);

        assertArrayEquals(EXTENDED_RANDOM_SERVER, context.getServerExtendedRandom());

        assertArrayEquals(concatClientRandom, context.getClientRandom());
        assertArrayEquals(concatServerRandom, context.getServerRandom());
    }

    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[0], 0) instanceof ExtendedRandomExtensionParser);
    }

    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new ExtendedRandomExtensionMessage()) instanceof ExtendedRandomExtensionPreparator);
    }

    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new ExtendedRandomExtensionMessage()) instanceof ExtendedRandomExtensionSerializer);
    }

}
