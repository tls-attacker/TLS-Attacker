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
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
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

public class ChangeCompressionActionTest {

    private State state;
    private TlsContext tlsContext;
    private ChangeCompressionAction action;

    @Before
    public void setUp() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, CryptoException {
        Config config = Config.createConfig();
        action = new ChangeCompressionAction(CompressionMethod.LZS);
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
        assertEquals(action.getNewValue(), CompressionMethod.LZS);
        action.setNewValue(CompressionMethod.DEFLATE);
        assertEquals(action.getNewValue(), CompressionMethod.DEFLATE);
    }

    /**
     * Test of getNewValue method, of class ChangeCompressionAction.
     */
    @Test
    public void testGetNewValue() {
        assertEquals(action.getNewValue(), CompressionMethod.LZS);
    }

    /**
     * Test of getOldValue method, of class ChangeCompressionAction.
     */
    @Test
    public void testGetOldValue() {
        tlsContext.setSelectedCompressionMethod(CompressionMethod.NULL);
        action.execute(state);
        assertEquals(action.getOldValue(), CompressionMethod.NULL);
    }

    /**
     * Test of execute method, of class ChangeCompressionAction.
     */
    @Test
    public void testExecute() {
        tlsContext.setSelectedCompressionMethod(CompressionMethod.NULL);
        action.execute(state);
        assertEquals(action.getOldValue(), CompressionMethod.NULL);
        assertEquals(action.getNewValue(), CompressionMethod.LZS);
        assertEquals(tlsContext.getSelectedCompressionMethod(), CompressionMethod.LZS);
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
        ActionTestUtils.marshalingEmptyActionYieldsMinimalOutput(ChangeCompressionAction.class);
    }

    @Test
    @Category(SlowTests.class)
    public void marshalingAndUnmarshalingEmptyObjectYieldsEqualObject() {
        ActionTestUtils.marshalingAndUnmarshalingEmptyObjectYieldsEqualObject(ChangeCompressionAction.class);
    }

    @Test
    @Category(SlowTests.class)
    public void marshalingAndUnmarshalingFilledObjectYieldsEqualObject() {
        ActionTestUtils.marshalingAndUnmarshalingFilledObjectYieldsEqualObject(action);
    }

}
