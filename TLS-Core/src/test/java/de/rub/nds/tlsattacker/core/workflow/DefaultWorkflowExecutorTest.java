/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.recording.ClientRecordingTcpTransportHandler;
import java.io.IOException;
import java.util.Random;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class DefaultWorkflowExecutorTest {

    private ClientRecordingTcpTransportHandler transportHandler;

    private DefaultWorkflowExecutor workflowExecutorTest;

    public DefaultWorkflowExecutorTest() {
    }

    @Before
    public void setUp() {
        RandomHelper.setRandom(new Random(0));
    }

    /**
     * Test of executeWorkflow method, of class DefaultWorkflowExecutor.
     */
    @Test
    public void testFullWorkflowDeterminsitcWorkflow() throws IOException {
        Config c = Config.createConfig();
        c.setDefaultSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        c.setDefaultClientSupportedCiphersuites(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        c.setPort(4433);
        c.setHost("127.0.0.1");
        c.setWorkflowExecutorShouldOpen(false);
        c.setWorkflowTraceType(WorkflowTraceType.FULL);
        transportHandler = new ClientRecordingTcpTransportHandler(1000, "localhost", 4433);
        transportHandler.initialize();
        TlsContext context = new TlsContext(c);
        context.setTransportHandler(transportHandler);
        WorkflowExecutor executor = new DefaultWorkflowExecutor(context);
        try {
            executor.executeWorkflow();
        }catch(Exception E)
        {
            E.printStackTrace();
        }
        System.out.println("############################");
        for (byte[] bytes : transportHandler.getFetchDataCallList()) {
            System.out.println(ArrayConverter.bytesToHexString(bytes,false,false));
            System.out.println("-----------------------------------");
        }
        System.out.println("############################");
        
    }

}
