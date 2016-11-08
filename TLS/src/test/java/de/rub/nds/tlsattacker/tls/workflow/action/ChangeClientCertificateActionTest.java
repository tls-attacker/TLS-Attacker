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
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ActionExecutor;
import de.rub.nds.tlsattacker.unittest.ActionExecutorMock;
import de.rub.nds.tlsattacker.unittest.TestCertificates;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.JAXB;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author ic0ns
 */
public class ChangeClientCertificateActionTest {

    private TlsContext tlsContext;
    private TlsContext dtlsContext;

    private ActionExecutorMock executor;
    private ChangeClientCertificateAction action;

    public ChangeClientCertificateActionTest() {
    }

    @Before
    public void setUp() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        executor = new ActionExecutorMock();
        tlsContext = new TlsContext();
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        tlsContext.setRecordHandler(new RecordHandler(tlsContext));
        tlsContext.getRecordHandler().setRecordCipher(new TlsRecordBlockCipher(tlsContext));
        dtlsContext = new TlsContext();
        dtlsContext.setProtocolVersion(ProtocolVersion.DTLS12);
        dtlsContext.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        dtlsContext.setRecordHandler(new DtlsRecordHandler(dtlsContext));
        action = new ChangeClientCertificateAction(TestCertificates.getTestCertificate(), TestCertificates.getTestCertificateObject());
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
        tlsContext.setClientCertificate(TestCertificates.getTestCertificate());
        tlsContext.setX509ClientCertificateObject(TestCertificates.getTestCertificateObject());
        action.execute(tlsContext, executor);
        assertEquals(action.getOldValue(), TestCertificates.getTestCertificate());
    }

    /**
     * Test of getX509newValue method, of class ChangeClientCertificateAction.
     */
    @Test
    public void testGetX509newValue() {
        assertEquals(action.getX509newValue(), TestCertificates.getTestCertificateObject());
    }

    /**
     * Test of getX509oldValue method, of class ChangeClientCertificateAction.
     */
    @Test
    public void testGetX509oldValue() {
        tlsContext.setClientCertificate(TestCertificates.getTestCertificate());
        tlsContext.setX509ClientCertificateObject(TestCertificates.getTestCertificateObject());
        action.execute(tlsContext, executor);
        assertEquals(action.getX509oldValue(), TestCertificates.getTestCertificateObject());
    }

    /**
     * Test of execute method, of class ChangeClientCertificateAction.
     */
    @Test
    public void testExecute() {
        action.execute(tlsContext, executor);
        assertEquals(action.getX509newValue(), TestCertificates.getTestCertificateObject());
        assertEquals(action.getNewValue(), TestCertificates.getTestCertificate());
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
        TLSAction action2 = JAXB.unmarshal(new StringReader(writer.getBuffer().toString()), ChangeClientCertificateAction.class);
        assertEquals(action, action2);
    }

}
