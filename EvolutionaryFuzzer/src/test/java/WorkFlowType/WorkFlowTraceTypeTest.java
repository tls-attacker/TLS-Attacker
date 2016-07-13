/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package WorkFlowType;

import de.rub.nds.tlsattacker.eap.ClientHello;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class WorkFlowTraceTypeTest {

    public WorkFlowTraceTypeTest() {
    }

    /**
     * Test of equals method, of class WorkFlowTraceType.
     */
    @Test
    public void testEquals() {

	WorkFlowTraceType instance = new WorkFlowTraceType();
	instance.addMessageFlow(new MessageFlow(ClientHelloMessage.class, ConnectionEnd.CLIENT));
	WorkFlowTraceType instance2 = new WorkFlowTraceType();
	instance2.addMessageFlow(new MessageFlow(ClientHelloMessage.class, ConnectionEnd.SERVER));
	assertNotSame("Failure: Messageflows have Different Connection Ends, the WorkFlowType should not be equal",instance, instance2);
	instance2 = new WorkFlowTraceType();
	instance2.addMessageFlow(new MessageFlow(ClientHelloMessage.class, ConnectionEnd.CLIENT));
	assertEquals("Failure: MessageFlows are should be equal",instance, instance2);
	instance2 = new WorkFlowTraceType();
	instance2.addMessageFlow(new MessageFlow(ClientHelloMessage.class, ConnectionEnd.CLIENT));
	instance2.addMessageFlow(new MessageFlow(ClientHelloMessage.class, ConnectionEnd.CLIENT));
	assertNotSame("Failure: WorkFlowTraceTypes have different number of MessageFlows",instance, instance2);

    }

    /**
     * Test of clean method, of class WorkFlowTraceType.
     */
    @Test
    public void testClean() {
	WorkFlowTraceType instance = new WorkFlowTraceType();
	instance.addMessageFlow(new MessageFlow(ClientHelloMessage.class, ConnectionEnd.CLIENT));
	instance.addMessageFlow(new MessageFlow(ClientHelloMessage.class, ConnectionEnd.SERVER));
	instance.addMessageFlow(new MessageFlow(ClientHelloMessage.class, ConnectionEnd.CLIENT));
	instance.addMessageFlow(new MessageFlow(ClientHelloMessage.class, ConnectionEnd.CLIENT));
	WorkFlowTraceType instance2 = new WorkFlowTraceType();
	instance2.addMessageFlow(new MessageFlow(ClientHelloMessage.class, ConnectionEnd.CLIENT));
	instance2.addMessageFlow(new MessageFlow(ClientHelloMessage.class, ConnectionEnd.SERVER));
	instance.clean();
	assertEquals(instance, instance2);
    }

}
