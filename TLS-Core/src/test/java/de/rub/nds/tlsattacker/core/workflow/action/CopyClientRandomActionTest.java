/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import org.junit.jupiter.api.Test;

public class CopyClientRandomActionTest extends AbstractCopyActionTest<CopyClientRandomAction> {

    public CopyClientRandomActionTest() {
        super(new CopyClientRandomAction("src", "dst"), CopyClientRandomAction.class);
        src.setClientRandom(new byte[] { 1, 2 });
        dst.setClientRandom(new byte[] { 3, 4 });
    }

    @Test
    @Override
    public void testAliasesSetProperlyErrorSrc() {
        CopyClientRandomAction a = new CopyClientRandomAction(null, "dst");
        assertThrows(WorkflowExecutionException.class, a::assertAliasesSetProperly);
    }

    @Test
    @Override
    public void testAliasesSetProperlyErrorDst() {
        CopyClientRandomAction a = new CopyClientRandomAction("src", null);
        assertThrows(WorkflowExecutionException.class, a::assertAliasesSetProperly);
    }

    /**
     * Test of execute method, of class ChangeClientRandomAction.
     */
    @Test
    @Override
    public void testExecute() throws Exception {
        super.testExecute();
        assertArrayEquals(src.getClientRandom(), dst.getClientRandom());
        assertArrayEquals(new byte[] { 1, 2 }, src.getClientRandom());
    }

    /**
     * Test of equals method, of class ChangeClientRandomAction.
     */
    @Test
    public void testEquals() {
        assertEquals(action, action);
        assertNotEquals(action, new CopyClientRandomAction("src", "null"));
        assertNotEquals(action, new CopyClientRandomAction("null", "dst"));
        assertNotEquals(action, new CopyClientRandomAction("null", "null"));
    }
}
