/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action.executor;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.stream.StreamTransportHandler;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;

public class SendMessageHelperTest {

    private TlsContext context;

    private StreamTransportHandler transportHandler;

    private SendMessageHelper helper;

    @Before
    public void setUp() throws IOException {
        context = new TlsContext();
        transportHandler = new StreamTransportHandler(0, ConnectionEndType.CLIENT, new ByteArrayInputStream(
                new byte[] {}), new ByteArrayOutputStream());
        context.setTransportHandler(transportHandler);
        context.getTransportHandler().initialize();
        context.setRecordLayer(new TlsRecordLayer(context));
        helper = new SendMessageHelper();
    }

    /**
     * Test of sendMessages method, of class SendMessageHelper.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testSendMessages() throws Exception {
    }

    @Test
    public void testSendEmptyRecords() throws IOException {
        context.getConfig().setUseAllProvidedRecords(true);
        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        r.setMaxRecordLengthConfig(0);
        List<AbstractRecord> recordList = new LinkedList<>();
        recordList.add(r);
        helper.sendMessages(new LinkedList<ProtocolMessage>(), recordList, context);
        assertArrayEquals(new byte[] { 22, 03, 03, 0, 0 },
                ((ByteArrayOutputStream) transportHandler.getOutputStream()).toByteArray());

    }

}
