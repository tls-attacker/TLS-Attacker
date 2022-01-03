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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class SupportedVersionsExtensionHandlerTest {

    private SupportedVersionsExtensionHandler handler;
    private TlsContext context;

    public SupportedVersionsExtensionHandlerTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new SupportedVersionsExtensionHandler(context);
    }

    /**
     * Test of adjustContext method, of class SupportedVersionsExtensionHandler.
     */
    @Test
    public void testadjustContext() {
        SupportedVersionsExtensionMessage msg = new SupportedVersionsExtensionMessage();
        msg.setSupportedVersions(
            ArrayConverter.concatenate(ProtocolVersion.TLS12.getValue(), ProtocolVersion.TLS13.getValue()));
        handler.adjustContext(msg);
        assertTrue(context.getClientSupportedProtocolVersions().size() == 2);
        assertEquals(context.getHighestClientProtocolVersion().getValue(), ProtocolVersion.TLS13.getValue());
    }

    @Test
    public void testadjustContextBadVersions() {
        SupportedVersionsExtensionMessage msg = new SupportedVersionsExtensionMessage();
        msg.setSupportedVersions(new byte[] { 0, 1, 2, 3, 3, 3 });
        handler.adjustContext(msg);
        assertTrue(context.getClientSupportedProtocolVersions().size() == 1);
        assertEquals(context.getHighestClientProtocolVersion().getValue(), ProtocolVersion.TLS12.getValue());
    }
}
