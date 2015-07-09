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
package de.rub.nds.tlsattacker.tls.protocol.handshake.messages;

import de.rub.nds.tlsattacker.dtls.protocol.handshake.messagefields.HandshakeMessageDtlsFields;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;

/**
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 */
public class HandshakeMessageFactory {

    private final ProtocolVersion protocolVersion;

    public HandshakeMessageFactory(ProtocolVersion protocolVersion) {
	if (protocolVersion != ProtocolVersion.TLS12 || protocolVersion != ProtocolVersion.DTLS12) {
	    throw new UnsupportedOperationException("The specified protocol version '" + protocolVersion.toString()
		    + "' is not supported");
	}
	this.protocolVersion = protocolVersion;
    }

    public <T extends HandshakeMessage> T createHandshakeMessage(Class<T> handshakeMessageClass) {
	try {
	    switch (protocolVersion) {
		case TLS12:
		    return handshakeMessageClass.newInstance();
		case DTLS12:
		    T hm = handshakeMessageClass.newInstance();
		    hm.setMessageFields(new HandshakeMessageDtlsFields());
		    return hm;

		    // This case will not occur since an adequate
		    // protocolVersion is to be established by the constructor.
		    // Java needs it, though.
		default:
		    return null;
	    }
	} catch (InstantiationException | IllegalAccessException e) {
	    // Since createHandshakeMessage is called with hard-coded parameters
	    // only, this should not occur.
	    return null;
	}
    }

    public <T extends HandshakeMessage> T createHandshakeMessage(Class<T> handshakeMessageClass,
	    ConnectionEnd messageIssuer) {
	T hm = createHandshakeMessage(handshakeMessageClass);
	hm.setMessageIssuer(messageIssuer);
	return hm;
    }
}