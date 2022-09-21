/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action.executor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.stream.StreamTransportHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

public class SendMessageHelperTest {

    private TlsContext context;

    private StreamTransportHandler transportHandler;

    private SendMessageHelper helper;

    @BeforeEach
    public void setUp() throws IOException {
        context = new TlsContext();
        transportHandler = new StreamTransportHandler(0, 0, ConnectionEndType.CLIENT,
            new ByteArrayInputStream(new byte[] {}), new ByteArrayOutputStream());
        context.setTransportHandler(transportHandler);
        context.getTransportHandler().initialize();
        context.setRecordLayer(new TlsRecordLayer(context));
        helper = new SendMessageHelper();
    }

    /**
     * Test of sendMessages method, of class SendMessageHelper.
     *
     */
    @Test
    @Disabled("Not implemented")
    public void testSendMessages() {
    }

    @Test
    public void testSendEmptyRecords() throws IOException {
        context.getConfig().setUseAllProvidedRecords(true);
        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        r.setMaxRecordLengthConfig(0);
        List<AbstractRecord> recordList = new LinkedList<>();
        recordList.add(r);
        helper.sendMessages(new LinkedList<>(), new LinkedList<>(), recordList, context);
        assertArrayEquals(new byte[] { 22, 3, 3, 0, 0 },
            ((ByteArrayOutputStream) transportHandler.getOutputStream()).toByteArray());

    }
}
