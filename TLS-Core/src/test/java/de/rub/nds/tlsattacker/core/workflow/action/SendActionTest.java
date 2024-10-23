/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SendActionTest extends AbstractActionTest<SendAction> {

    public SendActionTest() {
        super(new SendAction(), SendAction.class);
        AlertMessage alert = new AlertMessage();
        alert.setConfig(AlertLevel.FATAL, AlertDescription.DECRYPT_ERROR);
        alert.setDescription(AlertDescription.DECODE_ERROR.getValue());
        alert.setLevel(AlertLevel.FATAL.getValue());
        action.setConfiguredMessages(List.of(alert));

        TlsContext context = state.getTlsContext();
        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        context.setTransportHandler(new FakeTcpTransportHandler(ConnectionEndType.CLIENT));
    }

    @Override
    @Test
    public void testExecute() throws Exception {
        super.testExecute();
        byte[] expectedBytes = ArrayConverter.hexStringToByteArray("15030300020233");
        testContents(expectedBytes);
    }

    @Test
    public void testPredefinedRecord() throws Exception {
        Record modifiedRecord = getModifiedRecord();
        byte[] expectedBytes = ArrayConverter.hexStringToByteArray("FF030300020233");
        action.setConfiguredRecords(List.of(modifiedRecord));
        super.testExecute();
        testContents(expectedBytes);
    }

    private Record getModifiedRecord() {
        Record modifiedRecord = new Record();
        modifiedRecord.setContentType(Modifiable.explicit((byte) 255));
        return modifiedRecord;
    }

    @Test
    public void testPredefinedMultipleRecords() throws Exception {
        Record modifiedRecord = getModifiedRecord();
        Record shortRecord = new Record();
        shortRecord.setMaxRecordLengthConfig(1);
        action.setConfiguredRecords(List.of(shortRecord, modifiedRecord));
        byte[] expectedBytes = ArrayConverter.hexStringToByteArray("150303000102FF0303000133");
        super.testExecute();
        testContents(expectedBytes);
    }

    public void testContents(byte[] expectedBytes) {
        FakeTcpTransportHandler fakeTransportHandler =
                (FakeTcpTransportHandler) state.getTlsContext().getTransportHandler();
        byte[] sentBytes = fakeTransportHandler.getSentBytes();
        Assertions.assertArrayEquals(expectedBytes, sentBytes);
    }
}
