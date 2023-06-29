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

public class CopyServerRandomActionTest extends AbstractCopyActionTest<CopyServerRandomAction> {

    public CopyServerRandomActionTest() {
        super(new CopyServerRandomAction("src", "dst"), CopyServerRandomAction.class);
        src.setServerRandom(new byte[] {1, 2});
        dst.setServerRandom(new byte[] {0, 0});
    }

    @Test
    @Override
    public void testAliasesSetProperlyErrorSrc() {
        CopyServerRandomAction a = new CopyServerRandomAction(null, "dst");
        assertThrows(ActionExecutionException.class, a::assertAliasesSetProperly);
    }

    @Test
    @Override
    public void testAliasesSetProperlyErrorDst() {
        CopyServerRandomAction a = new CopyServerRandomAction("src", null);
        assertThrows(ActionExecutionException.class, a::assertAliasesSetProperly);
    }

    /** Test of execute method, of class ChangeServerRandomAction. */
    @Test
    @Override
    public void testExecute() throws Exception {
        super.testExecute();
        assertArrayEquals(src.getServerRandom(), dst.getServerRandom());
        assertArrayEquals(new byte[] {1, 2}, src.getServerRandom());
    }

    /** Test of equals method, of class ChangeServerRandomAction. */
    @Test
    public void testEquals() {
        assertEquals(action, action);
        assertNotEquals(action, new CopyServerRandomAction("src", "null"));
        assertNotEquals(action, new CopyServerRandomAction("null", "dst"));
        assertNotEquals(action, new CopyServerRandomAction("null", "null"));
    }
}
