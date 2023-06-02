/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.record.Record;
import java.util.LinkedList;
import org.junit.jupiter.api.Test;

public class CopyBufferedRecordsActionTest
        extends AbstractCopyActionTest<CopyBufferedRecordsAction> {

    public CopyBufferedRecordsActionTest() {
        super(new CopyBufferedRecordsAction("src", "dst"), CopyBufferedRecordsAction.class);
    }

    @Test
    @Override
    public void testAliasesSetProperlyErrorSrc() {
        CopyBufferedRecordsAction a = new CopyBufferedRecordsAction(null, "dst");
        assertThrows(ActionExecutionException.class, a::assertAliasesSetProperly);
    }

    @Test
    @Override
    public void testAliasesSetProperlyErrorDst() {
        CopyBufferedRecordsAction a = new CopyBufferedRecordsAction("src", null);
        assertThrows(ActionExecutionException.class, a::assertAliasesSetProperly);
    }

    @Test
    @Override
    public void testExecute() throws Exception {
        ModifiableByteArray byteArray = new ModifiableByteArray();
        Record record = new Record();
        LinkedList<Record> recordBuffer = new LinkedList<>();

        record.setProtocolMessageBytes(byteArray);
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        record.setMaxRecordLengthConfig(18);
        record.setCleanProtocolMessageBytes(new byte[1]);
        record.setCompleteRecordBytes(new byte[1]);
        recordBuffer.add(record);
        src.setRecordBuffer(recordBuffer);

        super.testExecute();
        assertSame(src.getRecordBuffer(), dst.getRecordBuffer());
    }
}
