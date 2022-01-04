/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.SRPExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

public class SrpExtensionHandlerTest {

    private static final byte[] SRP_IDENTIFIER = new byte[] { 0x00, 0x01, 0x02, 0x03 };
    private static final int SRP_IDENTIFIER_LENGTH = 4;
    private SRPExtensionHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new SRPExtensionHandler(context);
    }

    @Test
    public void testadjustContext() {
        SRPExtensionMessage msg = new SRPExtensionMessage();
        msg.setSrpIdentifier(SRP_IDENTIFIER);
        msg.setSrpIdentifierLength(SRP_IDENTIFIER_LENGTH);

        handler.adjustContext(msg);

        assertArrayEquals(SRP_IDENTIFIER, context.getSecureRemotePasswordExtensionIdentifier());
    }
}
