/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.record.cipher.RecordBlockCipher;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.JAXB;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ChangeCipherSuiteActionTest {

    private TlsContext tlsContext;

    private ChangeCipherSuiteAction action;

    @Before
    public void setUp() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidKeyException, InvalidAlgorithmParameterException, InvalidAlgorithmParameterException,
            InvalidAlgorithmParameterException, InvalidAlgorithmParameterException {
        tlsContext = new TlsContext();
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        tlsContext.setRecordLayer(new TlsRecordLayer(tlsContext));
        tlsContext.getRecordLayer().setRecordCipher(new RecordBlockCipher(tlsContext));
        action = new ChangeCipherSuiteAction(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256);
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
        action.execute(tlsContext);
    }

    /**
     * Test of getOldValue method, of class ChangeCipherSuiteAction.
     */
    @Test
    public void testGetOldValue() {
        action.execute(tlsContext);
        assertEquals(action.getOldValue(), CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
    }

    /**
     * Test of execute method, of class ChangeCipherSuiteAction.
     */
    @Test
    public void testExecute() {
        action.execute(tlsContext);
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
        action.execute(tlsContext);
        assertTrue(action.isExecuted());
        action.reset();
        assertFalse(action.isExecuted());
        action.execute(tlsContext);
        assertTrue(action.isExecuted());
    }

    @Test
    public void testJAXB() {
        StringWriter writer = new StringWriter();
        JAXB.marshal(action, writer);
        TLSAction action2 = JAXB.unmarshal(new StringReader(writer.getBuffer().toString()),
                ChangeCipherSuiteAction.class);
        assertEquals(action, action2);
    }

}
