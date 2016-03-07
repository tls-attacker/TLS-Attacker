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
package de.rub.nds.tlsattacker.tls.protocol.application.handlers;

import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.application.messages.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ApplicationHandler extends ProtocolMessageHandler<ApplicationMessage> {

    public ApplicationHandler(TlsContext tlsContext) {
	super(tlsContext);
	this.correctProtocolMessageClass = ApplicationMessage.class;
    }

    @Override
    public byte[] prepareMessageAction() {
	protocolMessage.setData("test".getBytes());
	byte[] result = protocolMessage.getData().getValue();
	return result;
    }

    @Override
    public int parseMessageAction(byte[] message, int pointer) {

	protocolMessage.setData(Arrays.copyOfRange(message, pointer,message.length));
	//System.out.println(ArrayConverter.bytesToHexString(message));
	//System.out.println(ArrayConverter.bytesToHexString(Arrays.copyOf(message, pointer)));
	return message.length;

    }

}
