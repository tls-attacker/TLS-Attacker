/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import org.junit.jupiter.api.Test;

public class EllipticCurvesExtensionHandlerTest
        extends AbstractExtensionMessageHandlerTest<
                EllipticCurvesExtensionMessage, EllipticCurvesExtensionHandler> {

    public EllipticCurvesExtensionHandlerTest() {
        super(EllipticCurvesExtensionMessage::new, EllipticCurvesExtensionHandler::new);
    }

    /** Test of adjustContext method, of class EllipticCurvesExtensionHandler. */
    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        EllipticCurvesExtensionMessage msg = new EllipticCurvesExtensionMessage();
        msg.setSupportedGroups(new byte[] {0, 1, 0, 2});
        handler.adjustTLSExtensionContext(msg);
        assertEquals(2, context.getClientNamedGroupsList().size());
        assertSame(NamedGroup.SECT163K1, context.getClientNamedGroupsList().get(0));
        assertSame(NamedGroup.SECT163R1, context.getClientNamedGroupsList().get(1));
    }

    @Test
    public void testadjustContextUnknownCurve() {
        EllipticCurvesExtensionMessage msg = new EllipticCurvesExtensionMessage();
        msg.setSupportedGroups(new byte[] {(byte) 0xFF, (byte) 0xEE});
        handler.adjustContext(msg);
        assertTrue(context.getClientNamedGroupsList().isEmpty());
    }
}
