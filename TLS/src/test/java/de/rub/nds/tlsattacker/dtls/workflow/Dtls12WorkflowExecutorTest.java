/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.dtls.workflow;

import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.UDPTransportHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import static org.junit.Assert.fail;
import org.junit.Test;

/**
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 */
public class Dtls12WorkflowExecutorTest {

    public Dtls12WorkflowExecutorTest() {
    }

    @Test
    public void testExecuteWorkflow() {
	try {
	    DatagramSocket ds = new DatagramSocket(15243, InetAddress.getByName("127.0.0.1"));
	} catch (UnknownHostException | SocketException ex) {
	    fail(ex.getMessage());
	}
	TransportHandler th = new UDPTransportHandler();
	TlsContext tlsContext = new TlsContext();
	tlsContext.setProtocolVersion(ProtocolVersion.DTLS12);
	try {
	    th.initialize("127.0.0.1", 15243);
	} catch (IOException ex) {
	    fail(ex.getMessage());
	}

	Dtls12WorkflowExecutor workflowExecutor = new Dtls12WorkflowExecutor(th, tlsContext);

    }
}
