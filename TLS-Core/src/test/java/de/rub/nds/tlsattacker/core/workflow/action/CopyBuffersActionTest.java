/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import static org.junit.Assert.*;
import org.junit.Test;

public class CopyBuffersActionTest {

    @Test
    public void testGetSrcContextAlias() {
        CopyBuffersAction a = new CopyBuffersAction("src", "dst");
        assertEquals(a.getSrcContextAlias(), "src");
    }

    @Test
    public void testGetDstContextAlias() {
        CopyBuffersAction a = new CopyBuffersAction("src", "dst");
        assertEquals(a.getDstContextAlias(), "dst");
    }

    @Test
    public void testGetAllAliases() {
        CopyBuffersAction a = new CopyBuffersAction("src", "dst");
        Set<String> expected = new LinkedHashSet<>(Arrays.asList("dst", "src"));
        assertEquals(a.getAllAliases(), expected);
    }

    @Test
    public void testExecute() {
        CopyBuffersAction a = new CopyBuffersAction("src", "dst");
        WorkflowTrace trace = new WorkflowTrace();
        trace.addConnection(new OutboundConnection("src"));
        trace.addConnection(new OutboundConnection("dst"));
        trace.addTlsAction(a);
        State state = new State(trace);
        TlsContext src = state.getTlsContext("src");
        TlsContext dst = state.getTlsContext("dst");
        assertNotSame(src.getMessageBuffer(), dst.getMessageBuffer());
        assertNotSame(src.getRecordBuffer(), dst.getRecordBuffer());

        a.execute(state);
        assertSame(src.getMessageBuffer(), dst.getMessageBuffer());
        assertSame(src.getRecordBuffer(), dst.getRecordBuffer());
        assertTrue(a.isExecuted());
        assertTrue(a.executedAsPlanned());
    }

    @Test
    public void reset() {
        CopyBuffersAction a = new CopyBuffersAction("src", "dst");
        a.setExecuted(true);
        assertTrue(a.isExecuted());
        a.reset();
        assertFalse(a.isExecuted());
    }

    @Test(expected = WorkflowExecutionException.class)
    public void testAliasesSetProperlyErrorSrc() {
        CopyBuffersAction a = new CopyBuffersAction(null, "dst");
        a.assertAliasesSetProperly();
    }

    @Test(expected = WorkflowExecutionException.class)
    public void testAliasesSetProperlyErrorDst() {
        CopyBuffersAction a = new CopyBuffersAction("src", null);
        a.assertAliasesSetProperly();
    }
}