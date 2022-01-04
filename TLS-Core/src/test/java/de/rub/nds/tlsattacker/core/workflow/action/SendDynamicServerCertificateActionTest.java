/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.commons.lang3.ObjectUtils;
import org.bouncycastle.crypto.tls.CertificateStatus;
import org.bouncycastle.crypto.tls.CertificateStatusRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

public class SendDynamicServerCertificateActionTest {
    private State state;
    private Config config;
    private TlsContext tlsContext;

    private SendDynamicServerCertificateAction action;

    @Before
    public void setUp() throws Exception {
        // Setup action
        action = new SendDynamicServerCertificateAction();
        // Setup Server configuration
        config = Config.createConfig();
        config.setDefaultRunningMode(RunningModeType.SERVER);
        // see WorkflowConfigurationFactory.java
        // Action will be added if highest protocol version is lower than TLS
        // 1.3
        config.setHighestProtocolVersion(ProtocolVersion.TLS12);

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(action);

        state = new State(config, trace);

        tlsContext = state.getTlsContext();
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        tlsContext.setRecordLayer(new TlsRecordLayer(tlsContext));
        tlsContext.setTransportHandler(new FakeTransportHandler(ConnectionEndType.SERVER));
    }

    @Test(expected = WorkflowExecutionException.class)
    public void testExecute() {
        action.execute(state);
        assertTrue((action.executedAsPlanned()));
        assertTrue(action.isExecuted());
        // test if you can execute twice
        action.execute(state);
        // catch exception with expected annotation
    }

    @Test
    public void testToString() {
        assertTrue(action.toString().equals("Send Dynamic Certificate: (not executed)\n\tMessages:\n"));
        action.execute(state);
        assertTrue(action.toString().equals("Send Dynamic Certificate Action:\n\tMessages:CERTIFICATE, \n"));
    }

    @Test
    public void testToCompactString() {
        assertTrue(action.toCompactString().equals("SendDynamicServerCertificateAction [server] (no messages set)"));
        action.execute(state);
        assertTrue(action.toCompactString().equals("SendDynamicServerCertificateAction [server] (CERTIFICATE)"));
    }

    @Test
    public void testExecutedAsPlanned() {
        action.execute(state);
        assertTrue(action.executedAsPlanned());
    }

    @Test
    public void testSetRecords() {
        // check if set records are correct in out case: empty list
        action.execute(state);
        List<AbstractRecord> testRecords = new ArrayList<>();
        action.setRecords(testRecords);
        assertTrue(action.getSendRecords().equals(testRecords));
    }

    @Test
    public void testReset() {
        // execute action -> check if executed -> reset -> check if action not
        // executed!
        // -> check if you can execute action again
        assertFalse(action.isExecuted());
        action.execute(state);
        assertTrue(action.isExecuted());
        action.reset();
        assertFalse(action.isExecuted());
        action.execute(state);
        assertTrue(action.isExecuted());
    }

    @Test
    public void testGetSendMessages() {
        // check if the correct amount of messages have been sent
        assertTrue(action.getSendMessages().isEmpty());
        action.execute(state);
        assertTrue(
            action.getSendMessages().size() == 1 && action.getSendMessages().get(0) instanceof CertificateMessage);
    }

    @Test
    public void testGetSendRecords() {
        // check if send records contains the correct amount of sent records
        assertTrue(action.getSendRecords().isEmpty());
        action.execute(state);
        assertTrue(action.getSendRecords().size() == 1 && action.getSendRecords().get(0) instanceof Record);
    }

    @Test
    public void testEquals() {
        SendDynamicClientKeyExchangeAction compareAction1 = new SendDynamicClientKeyExchangeAction();
        SendDynamicClientKeyExchangeAction compareAction2 = new SendDynamicClientKeyExchangeAction();
        // check if the action equals another action/class
        assertFalse(action.equals(compareAction1));
        assertTrue(compareAction1.equals(compareAction2) && compareAction2.equals(compareAction1));
        // Null check
        assertFalse(action.equals(null));
        // check any other object
        assertFalse(action.equals(new Object()));
    }

    @Test
    public void testHashCode() {
        SendDynamicClientKeyExchangeAction compareAction1 = new SendDynamicClientKeyExchangeAction();
        SendDynamicClientKeyExchangeAction compareAction2 = new SendDynamicClientKeyExchangeAction();
        assertTrue(compareAction1.hashCode() == compareAction2.hashCode());
    }

    @Test
    public void testSendNoCertificate() {
        // Check if no certificate is sent with the corresponding cipher suite
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5);
        action.execute(state);
        assertTrue(action.getSendMessages().size() == 0 && action.getSendRecords().size() == 0);
    }
}
