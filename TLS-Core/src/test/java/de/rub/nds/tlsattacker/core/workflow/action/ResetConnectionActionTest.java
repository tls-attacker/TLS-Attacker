/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.layer.impl.RecordLayer;
import de.rub.nds.tlsattacker.core.record.cipher.CipherState;
import de.rub.nds.tlsattacker.core.record.cipher.RecordBlockCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordNullCipher;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
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
    private Context context;

    private ResetConnectionAction action;

    @Before
    public void setUp() throws NoSuchAlgorithmException, CryptoException, IOException {
        Config config = Config.createConfig();
        action = new ResetConnectionAction();
        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(action);
        state = new State(config, trace);
        context = state.getContext();
        context.getTcpContext().setTransportHandler(new FakeTransportHandler(ConnectionEndType.CLIENT));
        context.getTlsContext().setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        RecordCipher recordCipher = new RecordBlockCipher(context.getTlsContext(),
            new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), KeySetGenerator.generateKeySet(context.getTlsContext()),
                context.getTlsContext().isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        context.getTlsContext().getRecordLayer().updateEncryptionCipher(recordCipher);
        context.getTlsContext().getRecordLayer().updateDecryptionCipher(recordCipher);
        context.getTlsContext().setActiveClientKeySetType(Tls13KeySetType.EARLY_TRAFFIC_SECRETS);
        context.getTlsContext().setActiveServerKeySetType(Tls13KeySetType.EARLY_TRAFFIC_SECRETS);

    }

    @Test
    public void testExecute() throws IOException {
        action.execute(state);
        RecordLayer layer = context.getTlsContext().getRecordLayer();
        assertTrue(layer.getEncryptorCipher() instanceof RecordNullCipher);
        assertTrue(layer.getDecryptorCipher() instanceof RecordNullCipher);
        assertTrue(layer.getEncryptorCipher() instanceof RecordNullCipher);
        assertTrue(layer.getDecryptorCipher() instanceof RecordNullCipher);
        assertEquals(context.getTlsContext().getActiveClientKeySetType(), Tls13KeySetType.NONE);
        assertEquals(context.getTlsContext().getActiveServerKeySetType(), Tls13KeySetType.NONE);
        assertFalse(context.getTransportHandler().isClosed());
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
