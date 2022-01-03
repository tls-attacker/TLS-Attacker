/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedRandomExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtendedRandomExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtendedRandomExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtendedRandomExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class ExtendedRandomExtensionHandlerTest {
    private final byte[] EXTENDED_RANDOM_SHORT = new byte[0];
    private final byte[] EXTENDED_RANDOM_DEFAULT =
        ArrayConverter.hexStringToByteArray("AABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABB");
    private final byte[] EXTENDED_RANDOM_LONG =
        ArrayConverter.hexStringToByteArray("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    private final byte[] EXTENDED_RANDOM_CLIENT = ArrayConverter.hexStringToByteArray("AABBCCDDEEFF");
    private final byte[] EXTENDED_RANDOM_SERVER = ArrayConverter.hexStringToByteArray("112233445566");

    private TlsContext context;
    private ExtendedRandomExtensionHandler handler;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new ExtendedRandomExtensionHandler(context);
    }

    @Test
    public void testAdjustTLSContext() {
        // Short Extended Random Test
        ExtendedRandomExtensionMessage message = new ExtendedRandomExtensionMessage();
        message.setExtendedRandom(EXTENDED_RANDOM_SHORT);
        message.setExtendedRandomLength(EXTENDED_RANDOM_SHORT.length);
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        handler.adjustTLSContext(message);

        assertArrayEquals(EXTENDED_RANDOM_SHORT, context.getClientExtendedRandom());

        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        handler.adjustTLSContext(message);

        assertArrayEquals(EXTENDED_RANDOM_SHORT, context.getServerExtendedRandom());

        // Default length Extended Random Test
        message = new ExtendedRandomExtensionMessage();
        message.setExtendedRandom(EXTENDED_RANDOM_DEFAULT);
        message.setExtendedRandomLength(EXTENDED_RANDOM_DEFAULT.length);
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        handler.adjustTLSContext(message);

        assertArrayEquals(EXTENDED_RANDOM_DEFAULT, context.getClientExtendedRandom());

        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        handler.adjustTLSContext(message);

        assertArrayEquals(EXTENDED_RANDOM_DEFAULT, context.getServerExtendedRandom());

        // Long Extended Random Test
        message = new ExtendedRandomExtensionMessage();
        message.setExtendedRandom(EXTENDED_RANDOM_LONG);
        message.setExtendedRandomLength(EXTENDED_RANDOM_LONG.length);
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        handler.adjustTLSContext(message);

        assertArrayEquals(EXTENDED_RANDOM_LONG, context.getClientExtendedRandom());

        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        handler.adjustTLSContext(message);

        assertArrayEquals(EXTENDED_RANDOM_LONG, context.getServerExtendedRandom());

        // Generate same length Extended Random Test
        message = new ExtendedRandomExtensionMessage();
        message.setExtendedRandom(EXTENDED_RANDOM_DEFAULT);
        message.setExtendedRandomLength(EXTENDED_RANDOM_DEFAULT.length);
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.setServerExtendedRandom(EXTENDED_RANDOM_SHORT);
        handler.adjustTLSContext(message);

        assertEquals(EXTENDED_RANDOM_DEFAULT.length, context.getServerExtendedRandom().length);
    }

    @Test
    public void testConcatRandoms() {
        byte[] clientRandom = context.getClientRandom();
        byte[] serverRandom = context.getServerRandom();

        ExtendedRandomExtensionMessage message = new ExtendedRandomExtensionMessage();
        message.setExtendedRandom(EXTENDED_RANDOM_CLIENT);
        message.setExtendedRandomLength(EXTENDED_RANDOM_CLIENT.length);
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        handler.adjustTLSContext(message);

        message = new ExtendedRandomExtensionMessage();
        message.setExtendedRandom(EXTENDED_RANDOM_SERVER);
        message.setExtendedRandomLength(EXTENDED_RANDOM_SERVER.length);
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        handler.adjustTLSContext(message);

        byte[] concatClientRandom = ArrayConverter.concatenate(clientRandom, EXTENDED_RANDOM_CLIENT);
        byte[] concatServerRandom = ArrayConverter.concatenate(serverRandom, EXTENDED_RANDOM_SERVER);

        assertArrayEquals(concatClientRandom, context.getClientRandom());
        assertArrayEquals(concatServerRandom, context.getServerRandom());
    }

    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[0], 0, context.getConfig()) instanceof ExtendedRandomExtensionParser);
    }

    @Test
    public void testGetPreparator() {
        assertTrue(
            handler.getPreparator(new ExtendedRandomExtensionMessage()) instanceof ExtendedRandomExtensionPreparator);
    }

    @Test
    public void testGetSerializer() {
        assertTrue(
            handler.getSerializer(new ExtendedRandomExtensionMessage()) instanceof ExtendedRandomExtensionSerializer);
    }

}
