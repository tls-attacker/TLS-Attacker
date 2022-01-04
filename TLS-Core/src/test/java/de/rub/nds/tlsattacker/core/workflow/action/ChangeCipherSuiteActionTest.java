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
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.layer.impl.RecordLayer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.util.tests.SlowTests;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.*;

public class ChangeCipherSuiteActionTest {

    private State state;
    private TlsContext tlsContext;

    private ChangeCipherSuiteAction action;

    @Before
    public void setUp() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
        InvalidKeyException, InvalidAlgorithmParameterException, InvalidAlgorithmParameterException,
        InvalidAlgorithmParameterException, InvalidAlgorithmParameterException, CryptoException {
        Config config = Config.createConfig();
        action = new ChangeCipherSuiteAction(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256);
        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(action);
        state = new State(config, trace);
        tlsContext = state.getTlsContext();
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        tlsContext.setLayerStack(new LayerStack(tlsContext, new RecordLayer(tlsContext)));
    }

    /**
     * Test of getNewValue method, of class ChangeCipherSuiteAction.
     */
    @Test
    public void testGetNewValue() {
        assertEquals(action.getNewValue(), CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256);

    }

    /**
     * Test of setNewValue method, of class ChangeCipherSuiteAction.
     */
    @Test
    public void testSetNewValue() {
        assertEquals(action.getNewValue(), CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256);
        action.setNewValue(CipherSuite.TLS_FALLBACK_SCSV);
        assertEquals(action.getNewValue(), CipherSuite.TLS_FALLBACK_SCSV);

    }

    @Test
    public void testNoOld() {
        tlsContext.setSelectedCipherSuite(null);
        action.execute(state);
    }

    /**
     * Test of getOldValue method, of class ChangeCipherSuiteAction.
     */
    @Test
    public void testGetOldValue() {
        action.execute(state);
        assertEquals(action.getOldValue(), CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
    }

    /**
     * Test of execute method, of class ChangeCipherSuiteAction.
     */
    @Test
    public void testExecute() {
        action.execute(state);
        assertEquals(tlsContext.getSelectedCipherSuite(), action.getNewValue());
        // TODO check that cipher is reinitialised
        assertTrue(action.isExecuted());
    }

    /**
     * Test of reset method, of class ChangeCipherSuiteAction.
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
        ActionTestUtils.marshalingEmptyActionYieldsMinimalOutput(ChangeCipherSuiteAction.class);
    }

    @Test
    @Category(SlowTests.class)
    public void marshalingAndUnmarshalingEmptyObjectYieldsEqualObject() {
        ActionTestUtils.marshalingAndUnmarshalingEmptyObjectYieldsEqualObject(ChangeCipherSuiteAction.class);
    }

    @Test
    @Category(SlowTests.class)
    public void marshalingAndUnmarshalingFilledObjectYieldsEqualObject() {
        ActionTestUtils.marshalingAndUnmarshalingFilledObjectYieldsEqualObject(action);
    }

}
