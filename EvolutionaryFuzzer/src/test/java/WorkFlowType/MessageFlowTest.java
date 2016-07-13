/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package WorkFlowType;

import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class MessageFlowTest {

    public MessageFlowTest() {
    }

    /**
     * Test of equals method, of class MessageFlow.
     */
    @Test
    public void testEquals() {
	MessageFlow instance = new MessageFlow(ClientHelloMessage.class, ConnectionEnd.CLIENT);
	MessageFlow instance2 = new MessageFlow(ClientHelloMessage.class, ConnectionEnd.CLIENT);
	assertEquals(instance, instance2);
	instance2 = new MessageFlow(ClientHelloMessage.class, ConnectionEnd.SERVER);
	assertNotSame(instance, instance2);
	instance2 = new MessageFlow(ServerHelloDoneMessage.class, ConnectionEnd.CLIENT);
	assertNotSame(instance, instance2);
    }

}
