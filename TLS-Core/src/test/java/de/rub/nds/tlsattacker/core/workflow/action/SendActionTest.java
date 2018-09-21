/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.record.cipher.RecordBlockCipher;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.util.tests.SlowTests;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

public class SendActionTest {

    private State state;
    private TlsContext tlsContext;

    private SendAction action;

    @Before
    public void setUp() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, CryptoException {
        AlertMessage alert = new AlertMessage(Config.createConfig());
        alert.setConfig(AlertLevel.FATAL, AlertDescription.DECRYPT_ERROR);
        alert.setDescription(AlertDescription.DECODE_ERROR.getValue());
        alert.setLevel(AlertLevel.FATAL.getValue());
        action = new SendAction(alert);

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(action);
        state = new State(trace);

        tlsContext = state.getTlsContext();
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        tlsContext.setRecordLayer(new TlsRecordLayer(tlsContext));
        tlsContext.getRecordLayer().setRecordCipher(
                new RecordBlockCipher(tlsContext, KeySetGenerator.generateKeySet(tlsContext)));
        tlsContext.setTransportHandler(new FakeTransportHandler(ConnectionEndType.CLIENT));
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of execute method, of class SendAction.
     */
    @Test
    public void testExecute() {
        action.execute(state);
        action.executedAsPlanned(); // TODO check faketransporthandler
        assertTrue(action.isExecuted());
    }

    @Test
    public void testReset() {
        assertFalse(action.isExecuted());
        action.execute(state);
        assertTrue(action.isExecuted());
        action.reset();
        assertFalse(action.isExecuted());
        action.execute(state);
        assertTrue(action.isExecuted());
    }

    @Test
    @Category(SlowTests.class)
    public void marshalingEmptyActionYieldsMinimalOutput() {
        ActionTestUtils.marshalingEmptyActionYieldsMinimalOutput(SendAction.class);
    }

    @Test
    @Category(SlowTests.class)
    public void marshalingAndUnmarshalingEmptyObjectYieldsEqualObject() {
        ActionTestUtils.marshalingAndUnmarshalingEmptyObjectYieldsEqualObject(SendAction.class);
    }

    @Test
    @Category(SlowTests.class)
    public void marshalingAndUnmarshalingFilledObjectYieldsEqualObject() {
        ActionTestUtils.marshalingAndUnmarshalingFilledObjectYieldsEqualObject(action);
    }
}
