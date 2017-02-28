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
import de.rub.nds.tlsattacker.unittest.TestCertificates;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.JAXB;
import org.junit.After;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ChangeServerCertificateActionTest {

    private TlsContext tlsContext;
    private TlsContext dtlsContext;

    private ActionExecutorMock executor;
    private ChangeServerCertificateAction action;

    public ChangeServerCertificateActionTest() {
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
        dtlsContext.setSelectedProtocolVersion(ProtocolVersion.DTLS12);
        dtlsContext.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        dtlsContext.setRecordHandler(new DtlsRecordHandler(dtlsContext));
        action = new ChangeServerCertificateAction(TestCertificates.getTestCertificate());
        dtlsContext.getRecordHandler().setRecordCipher(new TlsRecordBlockCipher(dtlsContext));
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getNewValue method, of class ChangeClientCertificateAction.
     */
    @Test
    public void testGetNewValue() {
        assertEquals(action.getNewValue(), TestCertificates.getTestCertificate());

    }

    /**
     * Test of getOldValue method, of class ChangeClientCertificateAction.
     */
    @Test
    public void testGetOldValue() {
        tlsContext.setServerCertificate(TestCertificates.getTestCertificate());
        action.execute(tlsContext, executor);
        assertEquals(action.getOldValue(), TestCertificates.getTestCertificate());
    }

    /**
     * Test of execute method, of class ChangeClientCertificateAction.
     */
    @Test
    public void testExecute() {
        action.execute(tlsContext, executor);
        assertEquals(action.getNewValue(), TestCertificates.getTestCertificate());
        // TODO Check that context has changed
    }

    /**
     * Test of reset method, of class ChangeClientCertificateAction.
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
                ChangeServerCertificateAction.class);
        assertEquals(action, action2);
    }

}
