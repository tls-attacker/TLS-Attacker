/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.constants;

import de.rub.nds.tlsattacker.tls.protocol.handler.UnknownHandshakeMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.HelloVerifyRequestHandler;
import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.CertificateHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.CertificateRequestHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.CertificateVerifyHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.ClientHelloHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.DHClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.DHEServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.ECDHClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.ECDHEServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.FinishedHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.HelloRequestHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.RSAClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.ServerHelloDoneHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.ServerHelloHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import java.util.HashMap;
import java.util.Map;

/**
 * Also called Handshake Type
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public enum HandshakeMessageType {

    UNKNOWN,
    HELLO_REQUEST((byte) 0),
    CLIENT_HELLO((byte) 1),
    SERVER_HELLO((byte) 2),
    HELLO_VERIFY_REQUEST((byte) 3),
    NEW_SESSION_TICKET((byte) 4),
    CERTIFICATE((byte) 11),
    SERVER_KEY_EXCHANGE((byte) 12) {
        ProtocolMessageHandler<? extends ProtocolMessage> getMessageHandler(TlsContext tlsContext) {
            CipherSuite cs = tlsContext.getSelectedCipherSuite();
            KeyExchangeAlgorithm algorithm = AlgorithmResolver.getKeyExchangeAlgorithm(cs);
            switch (algorithm) {
                case EC_DIFFIE_HELLMAN:
                    return new ECDHEServerKeyExchangeHandler(tlsContext);
                case DHE_DSS:
                case DHE_RSA:
                case DH_ANON:
                case DH_DSS:
                case DH_RSA:
                    return new DHEServerKeyExchangeHandler(tlsContext);
                default:
                    throw new UnsupportedOperationException("Algorithm " + algorithm + " NOT supported yet.");
            }
        }
    },
    CERTIFICATE_REQUEST((byte) 13),
    SERVER_HELLO_DONE((byte) 14),
    CERTIFICATE_VERIFY((byte) 15),
    CLIENT_KEY_EXCHANGE((byte) 16) {

        ProtocolMessageHandler<? extends ProtocolMessage> getMessageHandler(TlsContext tlsContext) {
            CipherSuite cs = tlsContext.getSelectedCipherSuite();
            KeyExchangeAlgorithm algorithm = AlgorithmResolver.getKeyExchangeAlgorithm(cs);
            switch (algorithm) {
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
                    throw new UnsupportedOperationException("Algorithm " + algorithm + " NOT supported yet.");
            }
        }
    },
    FINISHED((byte) 20);

    private int value;

    private ConnectionEnd messageSender;

    private static final Map<Byte, HandshakeMessageType> MAP;

    private HandshakeMessageType(byte value) {
        this.value = value;
    }

    private HandshakeMessageType() {
        this.value = -1;
    }

    static {
        MAP = new HashMap<>();
        for (HandshakeMessageType cm : HandshakeMessageType.values()) {
            MAP.put((byte) cm.value, cm);
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
        return (byte) value;
    }

    public byte[] getArrayValue() {
        return new byte[] { (byte) value };
    }

    public final String getName() {
        return this.name();
    }
}
