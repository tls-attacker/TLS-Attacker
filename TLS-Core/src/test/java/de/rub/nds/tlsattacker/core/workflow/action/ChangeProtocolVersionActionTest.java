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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.cipher.RecordBlockCipher;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
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

public class ChangeProtocolVersionActionTest {

    private State state;
    private TlsContext tlsContext;
    private ChangeProtocolVersionAction action;

    @Before
    public void setUp() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, CryptoException {
        Config config = Config.createConfig();
        action = new ChangeProtocolVersionAction(ProtocolVersion.SSL2);
        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(action);
        state = new State(config, trace);
        tlsContext = state.getTlsContext();
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        tlsContext.setRecordLayer(new TlsRecordLayer(tlsContext));
        tlsContext.getRecordLayer().setRecordCipher(
                new RecordBlockCipher(tlsContext, KeySetGenerator.generateKeySet(tlsContext)));
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of setNewValue method, of class ChangeCompressionAction.
     */
    @Test
    public void testSetNewValue() {
        assertEquals(action.getNewValue(), ProtocolVersion.SSL2);
        action.setNewValue(ProtocolVersion.TLS11);
        assertEquals(action.getNewValue(), ProtocolVersion.TLS11);
    }

    /**
     * Test of getNewValue method, of class ChangeCompressionAction.
     */
    @Test
    public void testGetNewValue() {
        assertEquals(action.getNewValue(), ProtocolVersion.SSL2);
    }

    /**
     * Test of getOldValue method, of class ChangeCompressionAction.
     */
    @Test
    public void testGetOldValue() {
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        action.execute(state);
        assertEquals(action.getOldValue(), ProtocolVersion.TLS12);
    }

    /**
     * Test of execute method, of class ChangeCompressionAction.
     */
    @Test
    public void testExecute() {
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        action.execute(state);
        assertEquals(action.getOldValue(), ProtocolVersion.TLS12);
        assertEquals(action.getNewValue(), ProtocolVersion.SSL2);
        assertEquals(tlsContext.getSelectedProtocolVersion(), ProtocolVersion.SSL2);
        assertTrue(action.isExecuted());
    }

    /**
     * Test of reset method, of class ChangeCompressionAction.
     */
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
        ActionTestUtils.marshalingEmptyActionYieldsMinimalOutput(ChangeProtocolVersionAction.class);
    }

    @Test
    @Category(SlowTests.class)
    public void marshalingAndUnmarshalingEmptyObjectYieldsEqualObject() {
        ActionTestUtils.marshalingAndUnmarshalingEmptyObjectYieldsEqualObject(ChangeProtocolVersionAction.class);
    }

    @Test
    @Category(SlowTests.class)
    public void marshalingAndUnmarshalingFilledObjectYieldsEqualObject() {
        ActionTestUtils.marshalingAndUnmarshalingFilledObjectYieldsEqualObject(action);
    }

}
