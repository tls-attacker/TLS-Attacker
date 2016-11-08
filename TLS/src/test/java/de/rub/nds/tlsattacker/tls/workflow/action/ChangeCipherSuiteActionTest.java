/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow.action;

import de.rub.nds.tlsattacker.dtls.record.DtlsRecordHandler;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.crypto.TlsRecordBlockCipher;
import de.rub.nds.tlsattacker.tls.record.RecordHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.unittest.ActionExecutorMock;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.JAXB;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author ic0ns
 */
public class ChangeCipherSuiteActionTest {
    
    private TlsContext tlsContext;
    private TlsContext dtlsContext;
    
    private ActionExecutorMock executor;
    private ChangeCipherSuiteAction action;
    
    public ChangeCipherSuiteActionTest() {
        
    }
    
    @Before
    public void setUp() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidAlgorithmParameterException, InvalidAlgorithmParameterException, InvalidAlgorithmParameterException {
        executor = new ActionExecutorMock();
        tlsContext = new TlsContext();
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        tlsContext.setRecordHandler(new RecordHandler(tlsContext));
        tlsContext.getRecordHandler().setRecordCipher(new TlsRecordBlockCipher(tlsContext));
        dtlsContext = new TlsContext();
        dtlsContext.setProtocolVersion(ProtocolVersion.DTLS12);
        dtlsContext.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        dtlsContext.setRecordHandler(new DtlsRecordHandler(dtlsContext));
        action = new ChangeCipherSuiteAction(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256);
        dtlsContext.getRecordHandler().setRecordCipher(new TlsRecordBlockCipher(dtlsContext));
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

    /**
     * Test of getOldValue method, of class ChangeCipherSuiteAction.
     */
    @Test
    public void testGetOldValue() {
        action.execute(tlsContext, executor);
        assertEquals(action.getOldValue(), CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        action = new ChangeCipherSuiteAction(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256);
        action.execute(dtlsContext, executor);
        assertEquals(action.getOldValue(), CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        
    }

    /**
     * Test of execute method, of class ChangeCipherSuiteAction.
     */
    @Test
    public void testExecute() {
        action.execute(tlsContext, executor);
        assertEquals(tlsContext.getSelectedCipherSuite(), action.getNewValue());
        //TODO does not check if recordcipher is reinitialised
        action = new ChangeCipherSuiteAction(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256);
        action.execute(dtlsContext, executor);
        assertEquals(dtlsContext.getSelectedCipherSuite(), action.getNewValue());
        assertTrue(action.isExecuted());
    }

    /**
     * Test of reset method, of class ChangeCipherSuiteAction.
     */
    @Test
    public void testReset() {
        assertFalse(action.isExecuted());
        action.execute(tlsContext, executor);
        assertTrue(action.isExecuted());
        action.reset();
        assertFalse(action.isExecuted());
        action.execute(tlsContext, executor);
        assertTrue(action.isExecuted());
    }
    
    @Test
    public void testJAXB() {
        StringWriter writer = new StringWriter();
        JAXB.marshal(action, writer);
        TLSAction action2 = JAXB.unmarshal(new StringReader(writer.getBuffer().toString()), ChangeCipherSuiteAction.class);
        assertEquals(action, action2);
    }
    
}
