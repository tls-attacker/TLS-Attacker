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

public class CopyPreMasterSecretActionTest
        extends AbstractCopyActionTest<CopyPreMasterSecretAction> {

    public CopyPreMasterSecretActionTest() {
        super(new CopyPreMasterSecretAction("src", "dst"), CopyPreMasterSecretAction.class);
        src.setPreMasterSecret(new byte[] {1, 2});
        dst.setPreMasterSecret(new byte[] {3, 4});
    }

    @Test
    @Override
    public void testAliasesSetProperlyErrorSrc() {
        CopyPreMasterSecretAction action = new CopyPreMasterSecretAction(null, "dst");
        assertThrows(ActionExecutionException.class, action::assertAliasesSetProperly);
    }

    @Test
    @Override
    public void testAliasesSetProperlyErrorDst() {
        CopyPreMasterSecretAction action = new CopyPreMasterSecretAction("src", null);
        assertThrows(ActionExecutionException.class, action::assertAliasesSetProperly);
    }

    /** Test of execute method, of class CopyPreMasterSecretActionTest. */
    @Test
    @Override
    public void testExecute() throws Exception {
        super.testExecute();
        assertArrayEquals(src.getPreMasterSecret(), dst.getPreMasterSecret());
        assertArrayEquals(new byte[] {1, 2}, src.getPreMasterSecret());
    }

    /** Test of equals method, of class CopyPreMasterSecretAction. */
    @Test
    public void testEquals() {
        assertEquals(action, action);
        assertNotEquals(action, new CopyPreMasterSecretAction("src", "null"));
        assertNotEquals(action, new CopyPreMasterSecretAction("null", "dst"));
        assertNotEquals(action, new CopyPreMasterSecretAction("null", "null"));
    }
}
