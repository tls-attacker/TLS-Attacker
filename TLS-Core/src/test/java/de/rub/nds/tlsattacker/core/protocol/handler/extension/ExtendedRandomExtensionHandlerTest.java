/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedRandomExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.jupiter.api.Test;

public class ExtendedRandomExtensionHandlerTest
        extends AbstractExtensionMessageHandlerTest<
                ExtendedRandomExtensionMessage, ExtendedRandomExtensionHandler> {
    private final byte[] EXTENDED_RANDOM_SHORT = new byte[0];
    private final byte[] EXTENDED_RANDOM_DEFAULT =
            ArrayConverter.hexStringToByteArray(
                    "AABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABB");
    private final byte[] EXTENDED_RANDOM_LONG =
            ArrayConverter.hexStringToByteArray(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    private final byte[] EXTENDED_RANDOM_CLIENT =
            ArrayConverter.hexStringToByteArray("AABBCCDDEEFF");
    private final byte[] EXTENDED_RANDOM_SERVER =
            ArrayConverter.hexStringToByteArray("112233445566");

    public ExtendedRandomExtensionHandlerTest() {
        super(ExtendedRandomExtensionMessage::new, ExtendedRandomExtensionHandler::new);
    }

    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        // Short Extended Random Test
        ExtendedRandomExtensionMessage message = new ExtendedRandomExtensionMessage();
        message.setExtendedRandom(EXTENDED_RANDOM_SHORT);
        message.setExtendedRandomLength(EXTENDED_RANDOM_SHORT.length);
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        handler.adjustContext(message);

        assertArrayEquals(EXTENDED_RANDOM_SHORT, context.getClientExtendedRandom());

        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        handler.adjustContext(message);

        assertArrayEquals(EXTENDED_RANDOM_SHORT, context.getServerExtendedRandom());

        // Default length Extended Random Test
        message = new ExtendedRandomExtensionMessage();
        message.setExtendedRandom(EXTENDED_RANDOM_DEFAULT);
        message.setExtendedRandomLength(EXTENDED_RANDOM_DEFAULT.length);
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        handler.adjustContext(message);

        assertArrayEquals(EXTENDED_RANDOM_DEFAULT, context.getClientExtendedRandom());

        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        handler.adjustContext(message);

        assertArrayEquals(EXTENDED_RANDOM_DEFAULT, context.getServerExtendedRandom());

        // Long Extended Random Test
        message = new ExtendedRandomExtensionMessage();
        message.setExtendedRandom(EXTENDED_RANDOM_LONG);
        message.setExtendedRandomLength(EXTENDED_RANDOM_LONG.length);
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        handler.adjustContext(message);

        assertArrayEquals(EXTENDED_RANDOM_LONG, context.getClientExtendedRandom());

        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        handler.adjustContext(message);

        assertArrayEquals(EXTENDED_RANDOM_LONG, context.getServerExtendedRandom());

        // Generate same length Extended Random Test
        message = new ExtendedRandomExtensionMessage();
        message.setExtendedRandom(EXTENDED_RANDOM_DEFAULT);
        message.setExtendedRandomLength(EXTENDED_RANDOM_DEFAULT.length);
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.setServerExtendedRandom(EXTENDED_RANDOM_SHORT);
        handler.adjustContext(message);

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
        handler.adjustContext(message);

        message = new ExtendedRandomExtensionMessage();
        message.setExtendedRandom(EXTENDED_RANDOM_SERVER);
        message.setExtendedRandomLength(EXTENDED_RANDOM_SERVER.length);
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        handler.adjustContext(message);

        byte[] concatClientRandom =
                ArrayConverter.concatenate(clientRandom, EXTENDED_RANDOM_CLIENT);
        byte[] concatServerRandom =
                ArrayConverter.concatenate(serverRandom, EXTENDED_RANDOM_SERVER);

        assertArrayEquals(concatClientRandom, context.getClientRandom());
        assertArrayEquals(concatServerRandom, context.getServerRandom());
    }
}
