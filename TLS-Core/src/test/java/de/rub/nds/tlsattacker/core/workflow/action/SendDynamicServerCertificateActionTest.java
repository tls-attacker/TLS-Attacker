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

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.JAXBException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class SendDynamicServerCertificateActionTest
        extends AbstractActionTest<SendDynamicServerCertificateAction> {

    public SendDynamicServerCertificateActionTest() {
        super(new SendDynamicServerCertificateAction(), SendDynamicServerCertificateAction.class);

        TlsContext context = state.getTlsContext();
        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        context.setTransportHandler(new FakeTransportHandler(ConnectionEndType.SERVER));
    }

    @Override
    protected void createWorkflowTraceAndState() {
        config.setDefaultRunningMode(RunningModeType.SERVER);
        config.setHighestProtocolVersion(ProtocolVersion.TLS12);
        super.createWorkflowTraceAndState();
    }

    @Test
    @Override
    public void testExecute() throws Exception {
        super.testExecute();
    }

    @Test
    public void testToString() {
        assertEquals("Send Dynamic Certificate: (not executed)\n\tMessages:\n", action.toString());
        action.execute(state);
        assertEquals(
                "Send Dynamic Certificate Action:\n\tMessages:CERTIFICATE, \n", action.toString());
    }

    @Test
    public void testToCompactString() {
        assertEquals(
                "SendDynamicServerCertificateAction [server] (no messages set)",
                action.toCompactString());
        action.execute(state);
        assertEquals(
                "SendDynamicServerCertificateAction [server] (CERTIFICATE)",
                action.toCompactString());
    }

    @Test
    public void testSetRecords() {
        // check if set records are correct in out case: empty list
        action.execute(state);
        List<Record> testRecords = new ArrayList<>();
        action.setRecords(testRecords);
        assertEquals(testRecords, action.getSendRecords());
    }

    @Test
    public void testGetSendMessages() {
        // check if the correct amount of messages have been sent
        assertTrue(action.getSendMessages().isEmpty());
        action.execute(state);
        assertEquals(1, action.getSendMessages().size());
        assertTrue(action.getSendMessages().get(0) instanceof CertificateMessage);
    }

    @Test
    public void testGetSendRecords() {
        // check if send records contains the correct amount of sent records
        assertTrue(action.getSendRecords().isEmpty());
        action.execute(state);
        assertEquals(1, action.getSendRecords().size());
        assertTrue(action.getSendRecords().get(0) instanceof Record);
    }

    @Test
    public void testEquals() {
        assertEquals(action, action);
        // Null check
        assertNotEquals(null, action);
        // check any other object
        assertNotEquals(action, new Object());
    }

    @Test
    public void testHashCode() {
        SendDynamicServerCertificateAction compareAction1 =
                new SendDynamicServerCertificateAction();
        SendDynamicServerCertificateAction compareAction2 =
                new SendDynamicServerCertificateAction();
        assertEquals(compareAction1.hashCode(), compareAction2.hashCode());
    }

    @Test
    public void testSendNoCertificate() {
        // Check if no certificate is sent with the corresponding cipher suite
        state.getTlsContext()
                .setSelectedCipherSuite(CipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5);
        action.execute(state);
        assertEquals(0, action.getSendMessages().size());
        assertEquals(0, action.getSendRecords().size());
    }

    @Test
    @Disabled("Fix naming of SendDynamicServerCertificateAction in XML serialization")
    @Override
    public void testMarshalingEmptyActionYieldsMinimalOutput() throws JAXBException, IOException {
        super.testMarshalingEmptyActionYieldsMinimalOutput();
    }
}
