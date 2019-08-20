/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.*;
import org.junit.Test;

public class CopyBufferedRecordsActionTest {
    private CopyBufferedRecordsAction action = new CopyBufferedRecordsAction("src", "dst");
    private TlsContext context = new TlsContext();

    //@Before
    public void setUp(){

    }

    @Test
    public void testCopyField(){
        TlsContext src = new TlsContext();
        TlsContext dst = new TlsContext();

        action.copyField(src , dst);
        assertSame(src.getRecordBuffer(), dst.getRecordBuffer());
    }

    @Test
    public void testExecutedAsPlanned(){
        action.setExecuted(true);
        assertTrue(action.isExecuted());
        action.setExecuted(false);
        assertFalse(action.isExecuted());
    }


    @Test
    public void testReset(){
        action.reset();
        assertFalse(action.isExecuted());
    }


    //@After
    public void tearDown() {

    }
}