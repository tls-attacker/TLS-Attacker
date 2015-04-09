/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake.constants;

import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandlerBearer;
import de.rub.nds.tlsattacker.tls.protocol.handshake.handlers.ClientHelloHandler;
import de.rub.nds.tlsattacker.tls.protocol.handshake.handlers.CertificateHandler;
import de.rub.nds.tlsattacker.tls.protocol.handshake.handlers.CertificateRequestHandler;
import de.rub.nds.tlsattacker.tls.protocol.handshake.handlers.CertificateVerifyHandler;
import de.rub.nds.tlsattacker.tls.protocol.handshake.handlers.DHClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.protocol.handshake.handlers.DHEServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.protocol.handshake.handlers.ECDHClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.protocol.handshake.handlers.ECDHEServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.protocol.handshake.handlers.RSAClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.protocol.handshake.handlers.FinishedHandler;
import de.rub.nds.tlsattacker.tls.protocol.handshake.handlers.ServerHelloDoneHandler;
import de.rub.nds.tlsattacker.tls.protocol.handshake.handlers.ServerHelloHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.util.HashMap;
import java.util.Map;

/**
 * Also called Handshake Type
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public enum HandshakeMessageType implements ProtocolMessageHandlerBearer {

    HELLO_REQUEST((byte) 0),
    CLIENT_HELLO((byte) 1),
    SERVER_HELLO((byte) 2),
    NEW_SESSION_TICKET((byte) 4),
    CERTIFICATE((byte) 11),
    SERVER_KEY_EXCHANGE((byte) 12),
    CERTIFICATE_REQUEST((byte) 13),
    SERVER_HELLO_DONE((byte) 14),
    CERTIFICATE_VERIFY((byte) 15),
    CLIENT_KEY_EXCHANGE((byte) 16),
    FINISHED((byte) 20);

    private byte value;

    private ConnectionEnd messageSender;

    private static final Map<Byte, HandshakeMessageType> MAP;

    private HandshakeMessageType(byte value) {
	this.value = value;
    }

    static {
	MAP = new HashMap<>();
	for (HandshakeMessageType cm : HandshakeMessageType.values()) {
	    MAP.put(cm.value, cm);
	}
    }

    public static HandshakeMessageType getMessageType(byte value) {
	return MAP.get(value);
    }

    public static HandshakeMessageType getMessageType(byte value, ConnectionEnd messageSender) {
	HandshakeMessageType type = MAP.get(value);
	type.messageSender = messageSender;
	return type;
    }

    public byte getValue() {
	return value;
    }

    public byte[] getArrayValue() {
	return new byte[] { value };
    }

    public final String getName() {
	return this.name();
    }

    @Override
    public ProtocolMessageHandler getProtocolMessageHandler(TlsContext tlsContext) {
	CipherSuite cs = tlsContext.getSelectedCipherSuite();
	ProtocolMessageHandler pmh = null;
	switch (getMessageType(value)) {
	    case CLIENT_HELLO:
		pmh = new ClientHelloHandler(tlsContext);
		break;
	    case SERVER_HELLO:
		pmh = new ServerHelloHandler(tlsContext);
		break;
	    case CERTIFICATE:
		pmh = new CertificateHandler(tlsContext);
		break;
	    case SERVER_KEY_EXCHANGE:
		switch (KeyExchangeAlgorithm.getKeyExchangeAlgorithm(cs)) {
		    case EC_DIFFIE_HELLMAN:
			pmh = new ECDHEServerKeyExchangeHandler(tlsContext);
			break;
		    case DHE_DSS:
		    case DHE_RSA:
		    case DH_ANON:
		    case DH_DSS:
		    case DH_RSA:
			pmh = new DHEServerKeyExchangeHandler(tlsContext);
			break;
		}
		break;
	    case CERTIFICATE_REQUEST:
		pmh = new CertificateRequestHandler(tlsContext);
		break;
	    case SERVER_HELLO_DONE:
		pmh = new ServerHelloDoneHandler(tlsContext);
		break;
	    case CLIENT_KEY_EXCHANGE:
		switch (KeyExchangeAlgorithm.getKeyExchangeAlgorithm(cs)) {
		    case RSA:
			pmh = new RSAClientKeyExchangeHandler(tlsContext);
			break;
		    case EC_DIFFIE_HELLMAN:
			pmh = new ECDHClientKeyExchangeHandler(tlsContext);
			break;
		    case DHE_DSS:
		    case DHE_RSA:
		    case DH_ANON:
		    case DH_DSS:
		    case DH_RSA:
			pmh = new DHClientKeyExchangeHandler(tlsContext);
			break;
		}
		break;
	    case CERTIFICATE_VERIFY:
		pmh = new CertificateVerifyHandler(tlsContext);
		break;
	    case FINISHED:
		pmh = new FinishedHandler(tlsContext);
		break;

	}
	if (pmh == null) {
	    throw new UnsupportedOperationException("Not supported yet.");
	}
	return pmh;
    }
}
