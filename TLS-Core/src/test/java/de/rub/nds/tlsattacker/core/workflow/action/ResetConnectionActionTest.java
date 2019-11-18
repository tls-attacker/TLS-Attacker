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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.cipher.RecordBlockCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordNullCipher;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.util.tests.SlowTests;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

public class ResetConnectionActionTest {

    private State state;
    private TlsContext tlsContext;

    private ResetConnectionAction action;

    @Before
    public void setUp() throws NoSuchAlgorithmException, CryptoException, IOException {
        Config config = Config.createConfig();
        action = new ResetConnectionAction();
        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(action);
        state = new State(config, trace);
        tlsContext = state.getTlsContext();
        tlsContext.setTransportHandler(new FakeTransportHandler(ConnectionEndType.CLIENT));
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        tlsContext.setRecordLayer(new TlsRecordLayer(tlsContext));
        tlsContext.getRecordLayer().setRecordCipher(
                new RecordBlockCipher(tlsContext, KeySetGenerator.generateKeySet(tlsContext)));
        tlsContext.getRecordLayer().updateEncryptionCipher();
        tlsContext.getRecordLayer().updateDecryptionCipher();
        tlsContext.setActiveClientKeySetType(Tls13KeySetType.EARLY_TRAFFIC_SECRETS);
        tlsContext.setActiveServerKeySetType(Tls13KeySetType.EARLY_TRAFFIC_SECRETS);

    }

    @Test
    public void testExecute() throws IOException {
        action.execute(state);
        TlsRecordLayer layer = TlsRecordLayer.class.cast(tlsContext.getRecordLayer());
        assertTrue(layer.getRecordCipher() instanceof RecordNullCipher);
        assertTrue(layer.getEncryptor() instanceof RecordNullCipher);
        assertTrue(layer.getDecryptor() instanceof RecordNullCipher);
        assertEquals(tlsContext.getActiveClientKeySetType(), Tls13KeySetType.NONE);
        assertEquals(tlsContext.getActiveServerKeySetType(), Tls13KeySetType.NONE);
        assertFalse(tlsContext.getTransportHandler().isClosed());
        assertTrue(action.isExecuted());
    }

    @Test
    public void testReset() throws IOException {
        action.execute(state);
        assertTrue(action.isExecuted());
        action.reset();
        assertFalse(action.isExecuted());
    }

    @Test
    @Category(SlowTests.class)
    public void marshalingEmptyActionYieldsMinimalOutput() {
        ActionTestUtils.marshalingEmptyActionYieldsMinimalOutput(ResetConnectionAction.class);
    }

    @Test
    @Category(SlowTests.class)
    public void marshalingAndUnmarshalingEmptyObjectYieldsEqualObject() {
        ActionTestUtils.marshalingAndUnmarshalingEmptyObjectYieldsEqualObject(ResetConnectionAction.class);
    }

    @Test
    @Category(SlowTests.class)
    public void marshalingAndUnmarshalingFilledObjectYieldsEqualObject() {
        ActionTestUtils.marshalingAndUnmarshalingFilledObjectYieldsEqualObject(action);
    }

}
