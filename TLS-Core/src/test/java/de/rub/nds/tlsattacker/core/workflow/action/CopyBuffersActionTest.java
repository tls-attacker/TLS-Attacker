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

public class CopyBuffersActionTest extends AbstractCopyActionTest<CopyBuffersAction> {

    public CopyBuffersActionTest() {
        super(new CopyBuffersAction("src", "dst"), CopyBuffersAction.class);
    }

    @Test
    @Override
    public void testAliasesSetProperlyErrorSrc() {
        CopyBuffersAction action = new CopyBuffersAction(null, "dst");
        assertThrows(ActionExecutionException.class, action::assertAliasesSetProperly);
    }

    @Test
    @Override
    public void testAliasesSetProperlyErrorDst() {
        CopyBuffersAction action = new CopyBuffersAction("src", null);
        assertThrows(ActionExecutionException.class, action::assertAliasesSetProperly);
    }

    @Test
    @Override
    public void testExecute() throws Exception {
        assertNotSame(src.getMessageBuffer(), dst.getMessageBuffer());
        assertNotSame(src.getRecordBuffer(), dst.getRecordBuffer());
        super.testExecute();
        assertSame(src.getMessageBuffer(), dst.getMessageBuffer());
        assertSame(src.getRecordBuffer(), dst.getRecordBuffer());
    }
}
