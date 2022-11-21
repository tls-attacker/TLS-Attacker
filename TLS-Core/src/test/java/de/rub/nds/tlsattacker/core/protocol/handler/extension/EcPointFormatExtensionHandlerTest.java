/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import org.junit.jupiter.api.Test;

public class EcPointFormatExtensionHandlerTest
    extends AbstractExtensionMessageHandlerTest<ECPointFormatExtensionMessage, EcPointFormatExtensionHandler> {

    public EcPointFormatExtensionHandlerTest() {
        super(ECPointFormatExtensionMessage::new, EcPointFormatExtensionHandler::new);
    }

    /**
     * Test of adjustTLSContext method, of class EcPointFormatExtensionHandler.
     */
    @Test
    @Override
    public void testAdjustTLSContext() {
        ECPointFormatExtensionMessage msg = new ECPointFormatExtensionMessage();
        msg.setPointFormats(new byte[] { 0, 1 });
        handler.adjustTLSContext(msg);
        assertEquals(2, context.getClientPointFormatsList().size());
        assertTrue(context.getClientPointFormatsList().contains(ECPointFormat.UNCOMPRESSED));
        assertTrue(context.getClientPointFormatsList().contains(ECPointFormat.ANSIX962_COMPRESSED_PRIME));
    }

    @Test
    public void testUnadjustableMessage() {
        ECPointFormatExtensionMessage msg = new ECPointFormatExtensionMessage();
        msg.setPointFormats(new byte[] { 5 });
        handler.adjustTLSContext(msg);
        assertTrue(context.getClientPointFormatsList().isEmpty());
    }

}
