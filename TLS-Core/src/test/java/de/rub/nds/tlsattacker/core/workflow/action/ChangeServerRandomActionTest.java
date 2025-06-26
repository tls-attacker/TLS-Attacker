/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.Test;

public class ChangeServerRandomActionTest
        extends AbstractChangeActionTest<ChangeServerRandomAction> {

    public ChangeServerRandomActionTest() {
        super(new ChangeServerRandomAction(new byte[] {0, 1}), ChangeServerRandomAction.class);
    }

    /** Test of setNewValue method, of class ChangeClientRandomAction. */
    @Test
    @Override
    public void testSetNewValue() {
        assertArrayEquals(new byte[] {0, 1}, action.getNewValue());
        action.setNewValue(new byte[] {0});
        assertArrayEquals(new byte[] {0}, action.getNewValue());
    }

    /** Test of getNewValue method, of class ChangeClientRandomAction. */
    @Test
    @Override
    public void testGetNewValue() {
        assertArrayEquals(new byte[] {0, 1}, action.getNewValue());
    }

    /** Test of getOldValue method, of class ChangeClientRandomAction. */
    @Test
    @Override
    public void testGetOldValue() {
        context.setServerRandom(new byte[] {3});
        action.execute(state);
        assertArrayEquals(new byte[] {3}, action.getOldValue());
    }

    /** Test of execute method, of class ChangeClientRandomAction. */
    @Test
    @Override
    public void testExecute() throws Exception {
        context.setServerRandom(new byte[] {3});
        super.testExecute();
        assertArrayEquals(new byte[] {3}, action.getOldValue());
        assertArrayEquals(new byte[] {0, 1}, action.getNewValue());
        assertArrayEquals(new byte[] {0, 1}, context.getServerRandom());
    }
}
