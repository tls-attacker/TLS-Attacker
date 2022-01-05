/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class EllipticCurvesExtensionHandlerTest {

    private EllipticCurvesExtensionHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new EllipticCurvesExtensionHandler(context);
    }

    /**
     * Test of adjustContext method, of class EllipticCurvesExtensionHandler.
     */
    @Test
    public void testadjustContext() {
        EllipticCurvesExtensionMessage msg = new EllipticCurvesExtensionMessage();
        msg.setSupportedGroups(new byte[] { 0, 1, 0, 2 });
        handler.adjustContext(msg);
        assertTrue(context.getClientNamedGroupsList().size() == 2);
        assertTrue(context.getClientNamedGroupsList().get(0) == NamedGroup.SECT163K1);
        assertTrue(context.getClientNamedGroupsList().get(1) == NamedGroup.SECT163R1);
    }

    @Test
    public void testadjustContextUnknownCurve() {
        EllipticCurvesExtensionMessage msg = new EllipticCurvesExtensionMessage();
        msg.setSupportedGroups(new byte[] { (byte) 0xFF, (byte) 0xEE });
        handler.adjustContext(msg);
        assertTrue(context.getClientNamedGroupsList().isEmpty());
    }
}
