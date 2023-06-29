/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import org.junit.jupiter.api.Test;

public class CopyClientRandomActionTest extends AbstractCopyActionTest<CopyClientRandomAction> {

    public CopyClientRandomActionTest() {
        super(new CopyClientRandomAction("src", "dst"), CopyClientRandomAction.class);
        src.setClientRandom(new byte[] {1, 2});
        dst.setClientRandom(new byte[] {3, 4});
    }

    @Test
    @Override
    public void testAliasesSetProperlyErrorSrc() {
        CopyClientRandomAction action = new CopyClientRandomAction(null, "dst");
        assertThrows(ActionExecutionException.class, action::assertAliasesSetProperly);
    }

    @Test
    @Override
    public void testAliasesSetProperlyErrorDst() {
        CopyClientRandomAction action = new CopyClientRandomAction("src", null);
        assertThrows(ActionExecutionException.class, action::assertAliasesSetProperly);
    }

    /** Test of execute method, of class ChangeClientRandomAction. */
    @Test
    @Override
    public void testExecute() throws Exception {
        super.testExecute();
        assertArrayEquals(src.getClientRandom(), dst.getClientRandom());
        assertArrayEquals(new byte[] {1, 2}, src.getClientRandom());
    }

    /** Test of equals method, of class ChangeClientRandomAction. */
    @Test
    public void testEquals() {
        assertEquals(action, action);
        assertNotEquals(action, new CopyClientRandomAction("src", "null"));
        assertNotEquals(action, new CopyClientRandomAction("null", "dst"));
        assertNotEquals(action, new CopyClientRandomAction("null", "null"));
    }
}
