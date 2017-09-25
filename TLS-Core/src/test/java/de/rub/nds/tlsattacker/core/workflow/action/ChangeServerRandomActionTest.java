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
import de.rub.nds.tlsattacker.core.record.cipher.RecordBlockCipher;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.JAXB;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ChangeServerRandomActionTest {

    private State state;
    private TlsContext tlsContext;

    private ChangeServerRandomAction action;

    @Before
    public void setUp() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException {
        Config config = Config.createConfig();
        state = new State(config, new WorkflowTrace(config));
        tlsContext = state.getTlsContext();
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        tlsContext.setRecordLayer(new TlsRecordLayer(tlsContext));
        tlsContext.getRecordLayer().setRecordCipher(new RecordBlockCipher(tlsContext));
        action = new ChangeServerRandomAction(new byte[] { 0, 1 });
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of setNewValue method, of class ChangeClientRandomAction.
     */
    @Test
    public void testSetNewValue() {
        assertArrayEquals(action.getNewValue(), new byte[] { 0, 1 });
        action.setNewValue(new byte[] { 0 });
        assertArrayEquals(action.getNewValue(), new byte[] { 0 });
    }

    /**
     * Test of getNewValue method, of class ChangeClientRandomAction.
     */
    @Test
    public void testGetNewValue() {
        assertArrayEquals(action.getNewValue(), new byte[] { 0, 1 });
    }

    /**
     * Test of getOldValue method, of class ChangeClientRandomAction.
     */
    @Test
    public void testGetOldValue() {
        tlsContext.setServerRandom(new byte[] { 3 });
        action.execute(state);
        assertArrayEquals(action.getOldValue(), new byte[] { 3 });
    }

    /**
     * Test of execute method, of class ChangeClientRandomAction.
     */
    @Test
    public void testExecute() {
        tlsContext.setServerRandom(new byte[] { 3 });
        action.execute(state);
        assertArrayEquals(action.getOldValue(), new byte[] { 3 });
        assertArrayEquals(action.getNewValue(), new byte[] { 0, 1 });
        assertArrayEquals(tlsContext.getServerRandom(), new byte[] { 0, 1 });
        assertTrue(action.isExecuted());

    }

    /**
     * Test of reset method, of class ChangeClientRandomAction.
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
    public void testJAXB() {
        StringWriter writer = new StringWriter();
        JAXB.marshal(action, writer);
        TLSAction action2 = JAXB.unmarshal(new StringReader(writer.getBuffer().toString()),
                ChangeServerRandomAction.class);
        assertEquals(action, action2);
    }

}
