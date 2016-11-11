/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.workflow;

import tlsattacker.fuzzer.workflow.MessageFlow;
import tlsattacker.fuzzer.workflow.WorkflowTraceType;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import java.util.logging.Logger;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class WorkFlowTraceTypeTest {

    /**
     *
     */
    public WorkFlowTraceTypeTest() {
    }

    /**
     * Test of equals method, of class WorkflowTraceType.
     */
    @Test
    public void testEquals() {

        WorkflowTraceType instance = new WorkflowTraceType();
        instance.addMessageFlow(new MessageFlow(ClientHelloMessage.class, ConnectionEnd.CLIENT));
        WorkflowTraceType instance2 = new WorkflowTraceType();
        instance2.addMessageFlow(new MessageFlow(ClientHelloMessage.class, ConnectionEnd.SERVER));
        assertNotSame("Failure: Messageflows have Different Connection Ends, the WorkFlowType should not be equal",
                instance, instance2);
        instance2 = new WorkflowTraceType();
        instance2.addMessageFlow(new MessageFlow(ClientHelloMessage.class, ConnectionEnd.CLIENT));
        assertEquals("Failure: MessageFlows are should be equal", instance, instance2);
        instance2 = new WorkflowTraceType();
        instance2.addMessageFlow(new MessageFlow(ClientHelloMessage.class, ConnectionEnd.CLIENT));
        instance2.addMessageFlow(new MessageFlow(ClientHelloMessage.class, ConnectionEnd.CLIENT));
        assertNotSame("Failure: WorkFlowTraceTypes have different number of MessageFlows", instance, instance2);

    }

    /**
     * Test of clean method, of class WorkflowTraceType.
     */
    @Test
    public void testClean() {
        WorkflowTraceType instance = new WorkflowTraceType();
        instance.addMessageFlow(new MessageFlow(ClientHelloMessage.class, ConnectionEnd.CLIENT));
        instance.addMessageFlow(new MessageFlow(ClientHelloMessage.class, ConnectionEnd.SERVER));
        instance.addMessageFlow(new MessageFlow(ClientHelloMessage.class, ConnectionEnd.CLIENT));
        instance.addMessageFlow(new MessageFlow(ClientHelloMessage.class, ConnectionEnd.CLIENT));
        WorkflowTraceType instance2 = new WorkflowTraceType();
        instance2.addMessageFlow(new MessageFlow(ClientHelloMessage.class, ConnectionEnd.CLIENT));
        instance2.addMessageFlow(new MessageFlow(ClientHelloMessage.class, ConnectionEnd.SERVER));
        instance.clean();
        assertEquals(instance, instance2);
    }

    private static final Logger LOG = Logger.getLogger(WorkFlowTraceTypeTest.class.getName());

}
