/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class ExtendedMasterSecretExtensionHandlerTest {

    private TlsContext context;
    private ExtendedMasterSecretExtensionHandler handler;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new ExtendedMasterSecretExtensionHandler(context);
    }

    @Test
    public void testadjustContext() {
        ExtendedMasterSecretExtensionMessage msg = new ExtendedMasterSecretExtensionMessage();
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        handler.adjustContext(msg);

        assertTrue(context.isExtensionProposed(ExtensionType.EXTENDED_MASTER_SECRET));
        assertFalse(context.isExtensionNegotiated(ExtensionType.EXTENDED_MASTER_SECRET));
        assertFalse(context.isUseExtendedMasterSecret());
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        handler.adjustContext(msg);
        assertTrue(context.isExtensionProposed(ExtensionType.EXTENDED_MASTER_SECRET));
        assertTrue(context.isExtensionNegotiated(ExtensionType.EXTENDED_MASTER_SECRET));
        assertTrue(context.isUseExtendedMasterSecret());
    }
}
