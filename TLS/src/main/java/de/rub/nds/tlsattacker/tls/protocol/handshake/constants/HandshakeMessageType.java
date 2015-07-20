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

    HELLO_REQUEST((byte) 0) {

	@Override
	ProtocolMessageHandler getMessageHandler(TlsContext tlsContext) {
	    throw new UnsupportedOperationException("Not supported yet.");
	}
    },
    CLIENT_HELLO((byte) 1) {

	@Override
	ProtocolMessageHandler getMessageHandler(TlsContext tlsContext) {
	    return new ClientHelloHandler(tlsContext);
	}
    },
    SERVER_HELLO((byte) 2) {

	@Override
	ProtocolMessageHandler getMessageHandler(TlsContext tlsContext) {
	    return new ServerHelloHandler(tlsContext);
	}
    },
    HELLO_VERIFY_REQUEST((byte) 3) {
	@Override
	ProtocolMessageHandler getMessageHandler(TlsContext tlsContext) {
	    throw new UnsupportedOperationException("Not supported yet.");
	}
    },
    NEW_SESSION_TICKET((byte) 4) {

	@Override
	ProtocolMessageHandler getMessageHandler(TlsContext tlsContext) {
	    throw new UnsupportedOperationException("Not supported yet.");
	}
    },
    CERTIFICATE((byte) 11) {

	@Override
	ProtocolMessageHandler getMessageHandler(TlsContext tlsContext) {
	    return new CertificateHandler(tlsContext);
	}
    },
    SERVER_KEY_EXCHANGE((byte) 12) {

	@Override
	ProtocolMessageHandler getMessageHandler(TlsContext tlsContext) {
	    CipherSuite cs = tlsContext.getSelectedCipherSuite();
	    switch (KeyExchangeAlgorithm.getKeyExchangeAlgorithm(cs)) {
		case EC_DIFFIE_HELLMAN:
		    return new ECDHEServerKeyExchangeHandler(tlsContext);
		case DHE_DSS:
		case DHE_RSA:
		case DH_ANON:
		case DH_DSS:
		case DH_RSA:
		    return new DHEServerKeyExchangeHandler(tlsContext);
		default:
		    throw new UnsupportedOperationException("Not supported yet.");
	    }
	}
    },
    CERTIFICATE_REQUEST((byte) 13) {

	@Override
	ProtocolMessageHandler getMessageHandler(TlsContext tlsContext) {
	    return new CertificateRequestHandler(tlsContext);
	}
    },
    SERVER_HELLO_DONE((byte) 14) {

	@Override
	ProtocolMessageHandler getMessageHandler(TlsContext tlsContext) {
	    return new ServerHelloDoneHandler(tlsContext);
	}
    },
    CERTIFICATE_VERIFY((byte) 15) {

	@Override
	ProtocolMessageHandler getMessageHandler(TlsContext tlsContext) {
	    return new CertificateVerifyHandler(tlsContext);
	}
    },
    CLIENT_KEY_EXCHANGE((byte) 16) {

	@Override
	ProtocolMessageHandler getMessageHandler(TlsContext tlsContext) {
	    CipherSuite cs = tlsContext.getSelectedCipherSuite();
	    switch (KeyExchangeAlgorithm.getKeyExchangeAlgorithm(cs)) {
		case RSA:
		    return new RSAClientKeyExchangeHandler(tlsContext);
		case EC_DIFFIE_HELLMAN:
		    return new ECDHClientKeyExchangeHandler(tlsContext);
		case DHE_DSS:
		case DHE_RSA:
		case DH_ANON:
		case DH_DSS:
		case DH_RSA:
		    return new DHClientKeyExchangeHandler(tlsContext);
		default:
		    throw new UnsupportedOperationException("Not supported yet.");
	    }
	}
    },
    FINISHED((byte) 20) {

	@Override
	ProtocolMessageHandler getMessageHandler(TlsContext tlsContext) {
	    return new FinishedHandler(tlsContext);
	}
    };

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

    abstract ProtocolMessageHandler getMessageHandler(TlsContext tlsContext);

    @Override
    public ProtocolMessageHandler getProtocolMessageHandler(TlsContext tlsContext) {
	return getMessageHandler(tlsContext);
    }
}
