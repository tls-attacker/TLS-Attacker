/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import static org.junit.Assert.assertArrayEquals;
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
    public void testadjustContext() {
        RenegotiationInfoExtensionMessage message = new RenegotiationInfoExtensionMessage();
        message.setRenegotiationInfo(EXTENSION_INFO);
        message.setExtensionLength(EXTENSION_LENGTH);
        handler.adjustContext(message);
        assertArrayEquals(context.getRenegotiationInfo(), EXTENSION_INFO);
    }
}
