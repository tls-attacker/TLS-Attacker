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
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.crypto.TlsRecordBlockCipher;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.record.RecordHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ActionExecutor;
import de.rub.nds.tlsattacker.unittest.ActionExecutorMock;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.JAXB;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ChangeProtocolVersionActionTest {

    private TlsContext tlsContext;
    private TlsContext dtlsContext;

    private ActionExecutorMock executor;
    private ChangeProtocolVersionAction action;

    public ChangeProtocolVersionActionTest() {
    }

    @Before
    public void setUp() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException {
        executor = new ActionExecutorMock();
        tlsContext = new TlsContext();
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        tlsContext.setRecordHandler(new RecordHandler(tlsContext));
        tlsContext.getRecordHandler().setRecordCipher(new TlsRecordBlockCipher(tlsContext));
        dtlsContext = new TlsContext();
        dtlsContext.getConfig().setProtocolVersion(ProtocolVersion.DTLS12);
        dtlsContext.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        dtlsContext.setRecordHandler(new DtlsRecordHandler(dtlsContext));
        action = new ChangeProtocolVersionAction(ProtocolVersion.SSL2);
        dtlsContext.getRecordHandler().setRecordCipher(new TlsRecordBlockCipher(dtlsContext));
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
        tlsContext.getConfig().setProtocolVersion(ProtocolVersion.TLS12);
        action.execute(tlsContext, executor);
        assertEquals(action.getOldValue(), ProtocolVersion.TLS12);
    }

    /**
     * Test of execute method, of class ChangeCompressionAction.
     */
    @Test
    public void testExecute() {
        tlsContext.getConfig().setProtocolVersion(ProtocolVersion.TLS12);
        action.execute(tlsContext, executor);
        assertEquals(action.getOldValue(), ProtocolVersion.TLS12);
        assertEquals(action.getNewValue(), ProtocolVersion.SSL2);
        assertEquals(tlsContext.getConfig().getProtocolVersion(), ProtocolVersion.SSL2);
        assertTrue(action.isExecuted());
    }

    /**
     * Test of reset method, of class ChangeCompressionAction.
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
        TLSAction action2 = JAXB.unmarshal(new StringReader(writer.getBuffer().toString()),
                ChangeProtocolVersionAction.class);
        assertEquals(action, action2);
    }

}
