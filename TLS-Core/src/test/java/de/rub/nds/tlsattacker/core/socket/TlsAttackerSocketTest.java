/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.socket;

import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionExecutor;
import de.rub.nds.tlsattacker.core.workflow.action.executor.DefaultActionExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.io.IOException;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * //TODO
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TlsAttackerSocketTest {

    public TlsAttackerSocketTest() {
    }

    @Before
    public void setUp() {
    }

    @Test
    public void exampleCode() throws IOException {
        GeneralDelegate delegate = new GeneralDelegate();
        TlsConfig config = TlsConfig.createConfig();
        delegate.setLogLevel(Level.OFF);
        delegate.applyDelegate(config);
        Security.addProvider(new BouncyCastleProvider());
        TlsContext context = new TlsContext(config);
        List<CipherSuite> cipherSuites = new LinkedList<>();
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        config.setSupportedCiphersuites(cipherSuites);
        config.setHost("127.0.0.1:4433");
        config.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
        config.setWorkflowExecutorShouldClose(false);
        DefaultWorkflowExecutor executor = new DefaultWorkflowExecutor(context);
        executor.executeWorkflow();
        TlsAttackerSocket socket = new TlsAttackerSocket(context);
        while (true) {
            String s = socket.receiveString();
            if(!s.equals(""))
            {
                System.out.println(s);
                socket.send(s.toUpperCase());
            }
        }
    }

    /**
     * Test of sendRawBytes method, of class TlsAttackerSocket.
     */
    @Test
    public void testSendRawBytes() throws Exception {

    }

    /**
     * Test of recieveRawBytes method, of class TlsAttackerSocket.
     */
    @Test
    public void testRecieveRawBytes() throws Exception {
    }

    /**
     * Test of send method, of class TlsAttackerSocket.
     */
    @Test
    public void testSend_String() {
    }

    /**
     * Test of send method, of class TlsAttackerSocket.
     */
    @Test
    public void testSend_byteArr() {
    }

    /**
     * Test of receiveBytes method, of class TlsAttackerSocket.
     */
    @Test
    public void testReceiveBytes() throws Exception {
    }

    /**
     * Test of receiveString method, of class TlsAttackerSocket.
     */
    @Test
    public void testReceiveString() throws Exception {
    }

}
