/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler.factory;

import de.rub.nds.tlsattacker.tls.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handler.AlertHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.ApplicationHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.CertificateHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.CertificateRequestHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.CertificateVerifyHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.ChangeCipherSpecHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.ClientHelloHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.ClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.DHClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.DHEServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.ECDHClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.ECDHEServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.FinishedHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.HandshakeMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.HeartbeatHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.HelloRequestHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.HelloVerifyRequestHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.RSAClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.ServerHelloDoneHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.ServerHelloHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.UnknownHandshakeMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.UnknownMessageHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class HandlerFactory {

    public static ProtocolMessageHandler getHandler(TlsContext context, ProtocolMessageType protocolType,
            HandshakeMessageType handshakeType) {
        switch (protocolType) {
            case HANDSHAKE:
                HandshakeMessageType hmt = HandshakeMessageType.getMessageType(handshakeType.getValue());
                return HandlerFactory.getHandshakeHandler(context, hmt);
            case CHANGE_CIPHER_SPEC:
                return new ChangeCipherSpecHandler(context);
            case ALERT:
                return new AlertHandler(context);
            case APPLICATION_DATA:
                return new ApplicationHandler(context);
            case HEARTBEAT:
                return new HeartbeatHandler(context);
            default:
                return new UnknownMessageHandler(context);
        }
    }

    public static HandshakeMessageHandler getHandshakeHandler(TlsContext context, HandshakeMessageType type) {
        switch (type) {
            case CERTIFICATE:
                return new CertificateHandler(context);
            case CERTIFICATE_REQUEST:
                return new CertificateRequestHandler(context);
            case CERTIFICATE_VERIFY:
                return new CertificateVerifyHandler(context);
            case CLIENT_HELLO:
                return new ClientHelloHandler(context);
            case CLIENT_KEY_EXCHANGE:
                return getClientKeyExchangeHandler(context);
            case FINISHED:
                return new FinishedHandler(context);
            case HELLO_REQUEST:
                return new HelloRequestHandler(context);
            case HELLO_VERIFY_REQUEST:
                return new HelloVerifyRequestHandler(context);
            case NEW_SESSION_TICKET:
                // TODO or should we give an UnknownHandshakeMessageHandler?
                throw new UnsupportedOperationException("Session Tickets are not supported yet!");
            case SERVER_HELLO:
                return new ServerHelloHandler(context);
            case SERVER_HELLO_DONE:
                return new ServerHelloDoneHandler(context);
            case SERVER_KEY_EXCHANGE:
                return getServerKeyExchangeHandler(context);
            case UNKNOWN:
                return new UnknownHandshakeMessageHandler(context);
        }
        throw new UnsupportedOperationException(
                "This MessageType is not specified in the HandshakeMessageHandler Factory!(bug)");
    }

    private static ClientKeyExchangeHandler getClientKeyExchangeHandler(TlsContext context) {
        CipherSuite cs = context.getSelectedCipherSuite();
        KeyExchangeAlgorithm algorithm = AlgorithmResolver.getKeyExchangeAlgorithm(cs);
        switch (algorithm) {
            case RSA:
                return new RSAClientKeyExchangeHandler(context);
            case EC_DIFFIE_HELLMAN:
                return new ECDHClientKeyExchangeHandler(context);
            case DHE_DSS:
            case DHE_RSA:
            case DH_ANON:
            case DH_DSS:
            case DH_RSA:
                return new DHClientKeyExchangeHandler(context);
            default:
                throw new UnsupportedOperationException("Algorithm " + algorithm + " NOT supported yet.");
        }
    }

    private static HandshakeMessageHandler getServerKeyExchangeHandler(TlsContext context) {// TODO
        // there
        // should
        // be
        // a
        // server
        // keyexchangeHandler
        CipherSuite cs = context.getSelectedCipherSuite();
        KeyExchangeAlgorithm algorithm = AlgorithmResolver.getKeyExchangeAlgorithm(cs);
        switch (algorithm) {
            case EC_DIFFIE_HELLMAN:
                return new ECDHEServerKeyExchangeHandler(context);
            case DHE_DSS:
            case DHE_RSA:
            case DH_ANON:
            case DH_DSS:
            case DH_RSA:
                return new DHEServerKeyExchangeHandler(context);
            default:
                throw new UnsupportedOperationException("Algorithm " + algorithm + " NOT supported yet.");
        }
    }
}
