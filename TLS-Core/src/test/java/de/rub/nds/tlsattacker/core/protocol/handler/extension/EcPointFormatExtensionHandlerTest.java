/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class EcPointFormatExtensionHandlerTest {

    private ECPointFormatExtensionHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new ECPointFormatExtensionHandler(context);
    }

    /**
     * Test of adjustContext method, of class EcPointFormatExtensionHandler.
     */
    @Test
    public void testadjustContext() {
        ECPointFormatExtensionMessage msg = new ECPointFormatExtensionMessage();
        msg.setPointFormats(new byte[] { 0, 1 });
        handler.adjustContext(msg);
        assertTrue(context.getClientPointFormatsList().size() == 2);
        assertTrue(context.getClientPointFormatsList().contains(ECPointFormat.UNCOMPRESSED));
        assertTrue(context.getClientPointFormatsList().contains(ECPointFormat.ANSIX962_COMPRESSED_PRIME));
    }

    public void testUnadjustableMessage() {
        ECPointFormatExtensionMessage msg = new ECPointFormatExtensionMessage();
        msg.setPointFormats(new byte[] { 5 });
        handler.adjustContext(msg);
        assertTrue(context.getClientPointFormatsList().isEmpty());
    }
}
