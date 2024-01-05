/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import org.junit.jupiter.api.Test;

public class ChangeCipherSuiteActionTest extends AbstractChangeActionTest<ChangeCipherSuiteAction> {

    public ChangeCipherSuiteActionTest() {
        super(
                new ChangeCipherSuiteAction(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256),
                ChangeCipherSuiteAction.class);
    }

    /** Test of getNewValue method, of class ChangeCipherSuiteAction. */
    @Test
    @Override
    public void testGetNewValue() {
        assertEquals(action.getNewValue(), CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256);
    }

    /** Test of setNewValue method, of class ChangeCipherSuiteAction. */
    @Test
    @Override
    public void testSetNewValue() {
        assertEquals(action.getNewValue(), CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256);
        action.setNewValue(CipherSuite.TLS_FALLBACK_SCSV);
        assertEquals(action.getNewValue(), CipherSuite.TLS_FALLBACK_SCSV);
    }

    @Test
    public void testNoOld() {
        context.setSelectedCipherSuite(null);
        assertDoesNotThrow(() -> action.execute(state));
    }

    /** Test of getOldValue method, of class ChangeCipherSuiteAction. */
    @Test
    @Override
    public void testGetOldValue() {
        action.execute(state);
        assertEquals(action.getOldValue(), CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
    }

    /** Test of execute method, of class ChangeCipherSuiteAction. */
    @Test
    @Override
    public void testExecute() throws Exception {
        super.testExecute();
        assertEquals(context.getSelectedCipherSuite(), action.getNewValue());
        // TODO check that cipher is reinitialised
    }
}
