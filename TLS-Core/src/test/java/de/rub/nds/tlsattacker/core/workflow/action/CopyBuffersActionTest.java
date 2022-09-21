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

public class CopyBuffersActionTest extends AbstractCopyActionTest<CopyBuffersAction> {

    public CopyBuffersActionTest() {
        super(new CopyBuffersAction("src", "dst"), CopyBuffersAction.class);
    }

    @Test
    @Override
    public void testAliasesSetProperlyErrorSrc() {
        CopyBuffersAction a = new CopyBuffersAction(null, "dst");
        assertThrows(WorkflowExecutionException.class, a::assertAliasesSetProperly);
    }

    @Test
    @Override
    public void testAliasesSetProperlyErrorDst() {
        CopyBuffersAction a = new CopyBuffersAction("src", null);
        assertThrows(WorkflowExecutionException.class, a::assertAliasesSetProperly);
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