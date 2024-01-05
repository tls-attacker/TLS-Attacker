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

import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import org.junit.jupiter.api.Test;

public class ChangeCompressionActionTest extends AbstractChangeActionTest<ChangeCompressionAction> {

    public ChangeCompressionActionTest() {
        super(new ChangeCompressionAction(CompressionMethod.LZS), ChangeCompressionAction.class);
    }

    /** Test of setNewValue method, of class ChangeCompressionAction. */
    @Test
    @Override
    public void testSetNewValue() {
        assertEquals(action.getNewValue(), CompressionMethod.LZS);
        action.setNewValue(CompressionMethod.DEFLATE);
        assertEquals(action.getNewValue(), CompressionMethod.DEFLATE);
    }

    /** Test of getNewValue method, of class ChangeCompressionAction. */
    @Test
    @Override
    public void testGetNewValue() {
        assertEquals(action.getNewValue(), CompressionMethod.LZS);
    }

    /** Test of getOldValue method, of class ChangeCompressionAction. */
    @Test
    @Override
    public void testGetOldValue() {
        context.setSelectedCompressionMethod(CompressionMethod.NULL);
        action.execute(state);
        assertEquals(action.getOldValue(), CompressionMethod.NULL);
    }

    /** Test of execute method, of class ChangeCompressionAction. */
    @Test
    @Override
    public void testExecute() throws Exception {
        context.setSelectedCompressionMethod(CompressionMethod.NULL);
        super.testExecute();
        assertEquals(action.getOldValue(), CompressionMethod.NULL);
        assertEquals(action.getNewValue(), CompressionMethod.LZS);
        assertEquals(context.getSelectedCompressionMethod(), CompressionMethod.LZS);
    }
}
