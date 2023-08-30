/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class WaitActionTest extends AbstractActionTest<WaitAction> {

    public WaitActionTest() {
        super(new WaitAction(10), WaitAction.class);
    }

    /** Test of execute method, of class WaitAction. */
    @Test
    @Override
    public void testExecute() throws Exception {
        long time = System.currentTimeMillis();
        super.testExecute();
        assertTrue(10L <= System.currentTimeMillis() - time);
    }
}
