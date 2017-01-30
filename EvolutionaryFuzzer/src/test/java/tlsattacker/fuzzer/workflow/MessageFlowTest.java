/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.workflow;

import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import org.junit.Test;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class MessageFlowTest {

    /**
     *
     */
    public MessageFlowTest() {
    }

    /**
     * Test of equals method, of class MessageFlow.
     */
    @Test
    public void testEquals() {
        MessageFlow instance = new MessageFlow(ClientHelloMessage.class, ConnectionEnd.CLIENT);
        MessageFlow instance2 = new MessageFlow(ClientHelloMessage.class, ConnectionEnd.CLIENT);
        assertEquals("Failure: Both MessageFlows are Equal", instance, instance2);
        instance2 = new MessageFlow(ClientHelloMessage.class, ConnectionEnd.SERVER);
        assertNotSame("Failure: MessageFlows have different MessageIssuers", instance, instance2);
        instance2 = new MessageFlow(ServerHelloDoneMessage.class, ConnectionEnd.CLIENT);
        assertNotSame("Failure: MessageFlows have different MessageClasses", instance, instance2);
    }

}
