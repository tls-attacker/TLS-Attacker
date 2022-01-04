/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.Before;
import org.junit.Test;

import java.util.LinkedList;

import static org.junit.Assert.*;

public class CopyBufferedRecordsActionTest {

    private CopyBufferedRecordsAction action;

    @Before
    public void setUp() {
        action = new CopyBufferedRecordsAction("src", "dst");
    }

    @Test
    public void testCopyField() {
        TlsContext src = new TlsContext();
        TlsContext dst = new TlsContext();
        ModifiableByteArray byteArray = new ModifiableByteArray();
        AbstractRecord record = new Record();
        LinkedList<AbstractRecord> recordBuffer = new LinkedList<>();

        record.setProtocolMessageBytes(byteArray);
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        record.setMaxRecordLengthConfig(18);
        record.setCleanProtocolMessageBytes(new byte[1]);
        record.setCompleteRecordBytes(new byte[1]);
        recordBuffer.add(record);
        src.setRecordBuffer(recordBuffer);

        action.copyField(src, dst);
        assertSame(src.getRecordBuffer(), dst.getRecordBuffer());
    }

    @Test
    public void testExecutedAsPlanned() {
        action.setExecuted(true);
        assertTrue(action.executedAsPlanned());
        action.setExecuted(false);
        assertFalse(action.executedAsPlanned());
    }

    @Test
    public void testReset() {
        action.setExecuted(true);
        action.reset();
        assertFalse(action.isExecuted());
    }

}
