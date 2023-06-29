/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
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
        extends AbstractExtensionMessageHandlerTest<
                ECPointFormatExtensionMessage, ECPointFormatExtensionHandler> {

    public EcPointFormatExtensionHandlerTest() {
        super(ECPointFormatExtensionMessage::new, ECPointFormatExtensionHandler::new);
    }

    /** Test of adjustContext method, of class EcPointFormatExtensionHandler. */
    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        ECPointFormatExtensionMessage msg = new ECPointFormatExtensionMessage();
        msg.setPointFormats(new byte[] {0, 1});
        handler.adjustTLSExtensionContext(msg);
        assertEquals(2, context.getClientPointFormatsList().size());
        assertTrue(context.getClientPointFormatsList().contains(ECPointFormat.UNCOMPRESSED));
        assertTrue(
                context.getClientPointFormatsList()
                        .contains(ECPointFormat.ANSIX962_COMPRESSED_PRIME));
    }

    @Test
    public void testUnadjustableMessage() {
        ECPointFormatExtensionMessage msg = new ECPointFormatExtensionMessage();
        msg.setPointFormats(new byte[] {5});
        handler.adjustContext(msg);
        assertTrue(context.getClientPointFormatsList().isEmpty());
    }
}
