/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.factory;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.AlertHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ApplicationHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.CertificateHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.CertificateRequestHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.CertificateVerifyHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ChangeCipherSpecHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ClientHelloHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.DHClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.DHEServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ECDHClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ECDHEServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.EncryptedExtensionsHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.FinishedHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.HandshakeMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.HeartbeatHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.HelloRequestHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.HelloRetryRequestHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.HelloVerifyRequestHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.RSAClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ServerHelloDoneHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ServerHelloHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.UnknownHandshakeMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.UnknownMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ECPointFormatExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.EllipticCurvesExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtendedMasterSecretExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.HRRKeyShareExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.HeartbeatExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.KeyShareExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.MaxFragmentLengthExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.PaddingExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.RenegotiationInfoExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ServerNameIndicationExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.SessionTicketTLSExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.SignatureAndHashAlgorithmsExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.SignedCertificateTimestampExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.SupportedVersionsExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.TokenBindingExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.UnknownExtensionHandler;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class HandlerFactory {

    private static final Logger LOGGER = LogManager.getLogger("HandlerFactory");

    public static ProtocolMessageHandler getHandler(TlsContext context, ProtocolMessageType protocolType,
            HandshakeMessageType handshakeType) {
        if (protocolType == null) {
            return new UnknownHandshakeMessageHandler(context);
        }
        try {
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
        } catch (UnsupportedOperationException E) {
            // Could not get the correct handler, getting an
            // unknownMessageHandler instead(always successful)
            return new UnknownHandshakeMessageHandler(context);
        }
    }

    public static HandshakeMessageHandler getHandshakeHandler(TlsContext context, HandshakeMessageType type) {
        try {
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
                case ENCRYPTED_EXTENSIONS:
                    return new EncryptedExtensionsHandler(context);
                case FINISHED:
                    return new FinishedHandler(context);
                case HELLO_RETRY_REQUEST:
                    return new HelloRetryRequestHandler(context);
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
        } catch (UnsupportedOperationException E) {
            LOGGER.debug("Could not retrieve correct Handler, returning UnknownHandshakeHandler", E);
        }
        return new UnknownHandshakeMessageHandler(context);
    }

    /**
     * Returns the correct extension Handler for a specified ExtensionType in a
     * HandshakeMessage
     *
     * @param context
     *            Current TlsContext
     * @param type
     *            Type of the Extension
     * @param handshakeMessageType
     *            The HandshakeMessageType which contains the Extension
     * @return Correct ExtensionHandler
     */
    public static ExtensionHandler getExtensionHandler(TlsContext context, ExtensionType type,
            HandshakeMessageType handshakeMessageType) {
        try {
            switch (type) {
                case ALPN:
                    throw new UnsupportedOperationException(type.name() + " Extension are not supported yet");
                case CACHED_INFO:
                    throw new UnsupportedOperationException(type.name() + " Extension are not supported yet");
                case CERT_TYPE:
                    throw new UnsupportedOperationException(type.name() + " Extension are not supported yet");
                case CLIENT_AUTHZ:
                    throw new UnsupportedOperationException(type.name() + " Extension are not supported yet");
                case CLIENT_CERTIFICATE_TYPE:
                    throw new UnsupportedOperationException(type.name() + " Extension are not supported yet");
                case CLIENT_CERTIFICATE_URL:
                    throw new UnsupportedOperationException(type.name() + " Extension are not supported yet");
                case EC_POINT_FORMATS:
                    return new ECPointFormatExtensionHandler(context);
                case ELLIPTIC_CURVES:
                    return new EllipticCurvesExtensionHandler(context);
                case ENCRYPT_THEN_MAC:
                    throw new UnsupportedOperationException(type.name() + " Extension are not supported yet");
                case EXTENDED_MASTER_SECRET:
                    return new ExtendedMasterSecretExtensionHandler(context);
                case HEARTBEAT:
                    return new HeartbeatExtensionHandler(context);
                case KEY_SHARE:
                    if (handshakeMessageType == HandshakeMessageType.HELLO_RETRY_REQUEST) {
                        return new HRRKeyShareExtensionHandler(context);
                    }
                    return new KeyShareExtensionHandler(context);
                case MAX_FRAGMENT_LENGTH:
                    return new MaxFragmentLengthExtensionHandler(context);
                case PADDING:
                    return new PaddingExtensionHandler(context);
                case RENEGOTIATION_INFO:
                    return new RenegotiationInfoExtensionHandler(context);
                case SERVER_AUTHZ:
                    return new ServerNameIndicationExtensionHandler(context);
                case SERVER_CERTIFICATE_TYPE:
                    throw new UnsupportedOperationException(type.name() + " Extension are not supported yet");
                case SERVER_NAME_INDICATION:
                    return new ServerNameIndicationExtensionHandler(context);
                case SESSION_TICKET:
                    return new SessionTicketTLSExtensionHandler(context);
                case SIGNATURE_AND_HASH_ALGORITHMS:
                    return new SignatureAndHashAlgorithmsExtensionHandler(context);
                case SIGNED_CERTIFICATE_TIMESTAMP:
                    return new SignedCertificateTimestampExtensionHandler(context);
                case SRP:
                    throw new UnsupportedOperationException(type.name() + " Extension are not supported yet");
                case STATUS_REQUEST:
                    throw new UnsupportedOperationException(type.name() + " Extension are not supported yet");
                case STATUS_REQUEST_V2:
                    throw new UnsupportedOperationException(type.name() + " Extension are not supported yet");
                case SUPPORTED_VERSIONS:
                    return new SupportedVersionsExtensionHandler(context);
                case TOKEN_BINDING:
                    return new TokenBindingExtensionHandler(context);
                case TRUNCATED_HMAC:
                    throw new UnsupportedOperationException(type.name() + " Extension are not supported yet");
                case TRUSTED_CA_KEYS:
                    throw new UnsupportedOperationException(type.name() + " Extension are not supported yet");
                case UNKNOWN:
                    return new UnknownExtensionHandler(context);
                case USER_MAPPING:
                    throw new UnsupportedOperationException(type.name() + " Extension are not supported yet");
                case USE_SRTP:
                    throw new UnsupportedOperationException(type.name() + " Extension are not supported yet");
                default:
                    throw new UnsupportedOperationException(type.name() + " Extension are not supported yet");
            }

        } catch (UnsupportedOperationException E) {
            LOGGER.debug("Could not retrieve correct Handler, returning UnknownExtensionHandler", E);
        }
        return new UnknownExtensionHandler(context);
    }

    private static ClientKeyExchangeHandler getClientKeyExchangeHandler(TlsContext context) {
        CipherSuite cs = context.getSelectedCipherSuite();
        KeyExchangeAlgorithm algorithm = AlgorithmResolver.getKeyExchangeAlgorithm(cs);
        switch (algorithm) {
            case RSA:
                return new RSAClientKeyExchangeHandler(context);
            case ECDHE_ECDSA:
            case ECDH_ECDSA:
            case ECDH_RSA:
            case ECDHE_RSA:
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
            case ECDHE_ECDSA:
            case ECDH_ECDSA:
            case ECDH_RSA:
            case ECDHE_RSA:
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

    private HandlerFactory() {
    }
}
