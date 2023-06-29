/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import org.junit.jupiter.api.Test;

public class ChangeProtocolVersionActionTest
        extends AbstractChangeActionTest<ChangeProtocolVersionAction> {

    public ChangeProtocolVersionActionTest() {
        super(
                new ChangeProtocolVersionAction(ProtocolVersion.SSL2),
                ChangeProtocolVersionAction.class);
    }

    /** Test of setNewValue method, of class ChangeCompressionAction. */
    @Test
    @Override
    public void testSetNewValue() {
        assertEquals(action.getNewValue(), ProtocolVersion.SSL2);
        action.setNewValue(ProtocolVersion.TLS11);
        assertEquals(action.getNewValue(), ProtocolVersion.TLS11);
    }

    /** Test of getNewValue method, of class ChangeCompressionAction. */
    @Test
    @Override
    public void testGetNewValue() {
        assertEquals(action.getNewValue(), ProtocolVersion.SSL2);
    }

    /** Test of getOldValue method, of class ChangeCompressionAction. */
    @Test
    @Override
    public void testGetOldValue() {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        action.execute(state);
        assertEquals(action.getOldValue(), ProtocolVersion.TLS12);
    }

    /** Test of execute method, of class ChangeCompressionAction. */
    @Test
    @Override
    public void testExecute() throws Exception {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        super.testExecute();
        assertEquals(action.getOldValue(), ProtocolVersion.TLS12);
        assertEquals(action.getNewValue(), ProtocolVersion.SSL2);
        assertEquals(context.getSelectedProtocolVersion(), ProtocolVersion.SSL2);
    }
}
