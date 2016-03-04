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
package de.rub.nds.tlsattacker.tls.protocol.application;

import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class ApplicationHandler extends ProtocolMessageHandler<ApplicationMessage> {

    private static final Logger LOGGER = LogManager.getLogger(ApplicationHandler.class);

    public ApplicationHandler(TlsContext tlsContext) {
	super(tlsContext);
	this.correctProtocolMessageClass = ApplicationMessage.class;
    }

    @Override
    public byte[] prepareMessageAction() {
	String responseBody;
	if (tlsContext.getMyConnectionEnd() == ConnectionEnd.SERVER) {
	    String status = "Handshake successful!";
	    if (tlsContext.isSessionResumption()) {
		status = "Session Resumption successful!";
	    }
	    responseBody = "HTTP/1.1 200 OK\n" + "Server: localhost\n"
		    + "Content-Type: text/html; charset=ISO-8859-1\n" + "\n" + "<html>\n" + "<head>\n"
		    + "<title>HTTP</TITLE>\n" + "</head>\n" + "<body>\n" + "<p>" + status + "</p>\n" + "</body>\n"
		    + "</html>";
	} else {
	    if (tlsContext.getCertSecure() == null) {
		responseBody = "GET / HTTP/1.1\r\n" + "Host: " + tlsContext.getHost() + "\r\n\r\n";
	    } else {
		responseBody = "GET /" + tlsContext.getCertSecure() + " HTTP/1.1\r\n" + "Host: " + tlsContext.getHost()
			+ "\r\n\r\n";
	    }
	}
	System.out.println(responseBody);
	protocolMessage.setData(responseBody.getBytes());
	LOGGER.debug("MessageData: {}", ArrayConverter.bytesToHexString(protocolMessage.getData().getValue()));
	byte[] result = protocolMessage.getData().getValue();

	return result;
    }

    @Override
    public int parseMessageAction(byte[] message, int pointer) {
	String application = new String(message);
	System.out.println(application);
	protocolMessage.setData(message);
	protocolMessage.setCompleteResultingMessage(Arrays.copyOfRange(message, pointer, message.length));
	pointer = message.length;
	return pointer;
    }

}
