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
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
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
import java.util.ArrayList;
import java.util.List;
import javax.crypto.NoSuchPaddingException;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

public class ChangeContextValueActionTest {

    private State state;
    private TlsContext tlsContext;
    private ChangeContextValueAction<ProtocolVersion> action;
    private WorkflowTrace trace;

    @Before
    public void setUp() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
        InvalidAlgorithmParameterException, CryptoException {
        Config config = Config.createConfig();
        action = new ChangeContextValueAction<ProtocolVersion>("selectedProtocolVersion", ProtocolVersion.SSL2);
        trace = new WorkflowTrace();
        trace.addTlsAction(action);
        state = new State(config, trace);
        tlsContext = state.getTlsContext();
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        tlsContext.setRecordLayer(new TlsRecordLayer(tlsContext));
    }

    @After
    public void tearDown() {
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testException1() {
        ChangeContextValueAction<ProtocolVersion> b =
            (ChangeContextValueAction<ProtocolVersion>) trace.getTlsActions().get(0);
        b.getNewValueList();
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testException2() {
        trace.addTlsAction(new ChangeContextValueAction<CipherSuite>("", CipherSuite.GREASE_00,
            CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256));
        ChangeContextValueAction<CipherSuite> b = (ChangeContextValueAction<CipherSuite>) trace.getTlsActions().get(1);
        b.getNewValue();
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
        ActionTestUtils.marshalingEmptyActionYieldsMinimalOutput(ChangeContextValueAction.class);
    }

    @Test
    @Category(SlowTests.class)
    public void marshalingAndUnmarshalingEmptyObjectYieldsEqualObject() {
        ActionTestUtils.marshalingAndUnmarshalingEmptyObjectYieldsEqualObject(ChangeContextValueAction.class);
    }

    @Test
    @Category(SlowTests.class)
    public void marshalingAndUnmarshalingFilledObjectYieldsEqualObject() {
        List<CipherSuite> ls = new ArrayList<CipherSuite>();
        ls.add(CipherSuite.SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA);
        ls.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);

        ChangeContextValueAction<byte[]> action2 =
            new ChangeContextValueAction<byte[]>("handshakeSecret", new byte[] { 0x01, 0x02, 0x03 });
        ChangeContextValueAction<CipherSuite> action3 =
            new ChangeContextValueAction<CipherSuite>("clientSupportedCipherSuites", ls);
        ChangeContextValueAction<PRFAlgorithm> action4 =
            new ChangeContextValueAction<PRFAlgorithm>("prfAlgorithm", PRFAlgorithm.TLS_PRF_SHA256);

        trace.addTlsActions(action2);
        trace.addTlsActions(action3);
        trace.addTlsActions(action4);
        WorkflowTrace copy = state.getWorkflowTraceCopy();

        assertEquals(action, (ChangeContextValueAction<ProtocolVersion>) copy.getTlsActions().get(0));
        assertEquals(action2, (ChangeContextValueAction<byte[]>) copy.getTlsActions().get(1));
        assertEquals(action3, (ChangeContextValueAction<CipherSuite>) copy.getTlsActions().get(2));
        assertEquals(action4, (ChangeContextValueAction<PRFAlgorithm>) copy.getTlsActions().get(3));
    }
}
