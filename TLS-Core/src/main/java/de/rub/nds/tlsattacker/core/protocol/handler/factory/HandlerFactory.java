/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.factory;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.handler.AlertHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ApplicationMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.CertificateMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.CertificateRequestHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.CertificateStatusHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.CertificateVerifyHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ChangeCipherSpecHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ClientHelloHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.DHClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.DHEServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ECDHClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ECDHEServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.EncryptedExtensionsHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.EndOfEarlyDataHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.FinishedHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.GOSTClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.HandshakeMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.HeartbeatMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.HelloRequestHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.HelloVerifyRequestHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.KeyUpdateHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.NewSessionTicketHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.PWDClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.PWDServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.PskClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.PskDhClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.PskDheServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.PskEcDhClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.PskEcDheServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.PskRsaClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.PskServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.RSAClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ServerHelloDoneHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ServerHelloHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.SrpClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.SrpServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.SupplementalDataHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.UnknownHandshakeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.UnknownMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.AlpnExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.CachedInfoExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.CertificateStatusRequestExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.CertificateStatusRequestV2ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.CertificateTypeExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ClientAuthzExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ClientCertificateTypeExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ClientCertificateUrlExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.CookieExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.EarlyDataExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ECPointFormatExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.EllipticCurvesExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.EncryptThenMacExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.EncryptedServerNameIndicationExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtendedMasterSecretExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtendedRandomExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.GreaseExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.HeartbeatExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.KeyShareExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.MaxFragmentLengthExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.PSKKeyExchangeModesExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.PWDClearExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.PWDProtectExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.PaddingExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.PasswordSaltExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.PreSharedKeyExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.RecordSizeLimitExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.RenegotiationInfoExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ServerAuthzExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ServerCertificateTypeExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ServerNameIndicationExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.SessionTicketTLSExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.SignatureAndHashAlgorithmsExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.SignedCertificateTimestampExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.SRPExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.SrtpExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.SupportedVersionsExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.TokenBindingExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.TruncatedHmacExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.TrustedCaIndicationExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.UnknownExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.UserMappingExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CachedInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestV2ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientAuthzExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateUrlExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CookieExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EarlyDataExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedRandomExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSKKeyExchangeModesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDClearExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDProtectExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PasswordSaltExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RecordSizeLimitExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SRPExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerAuthzExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerCertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignedCertificateTimestampExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TruncatedHmacExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TrustedCaIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.UnknownExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.UserMappingExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HandlerFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    private static ClientKeyExchangeHandler<? extends ClientKeyExchangeMessage>
        getClientKeyExchangeHandler(TlsContext context) {
        CipherSuite cs = context.getChooser().getSelectedCipherSuite();
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
            case DHE_PSK:
                return new PskDhClientKeyExchangeHandler(context);
            case ECDHE_PSK:
                return new PskEcDhClientKeyExchangeHandler(context);
            case PSK_RSA:
                return new PskRsaClientKeyExchangeHandler(context);
            case PSK:
                return new PskClientKeyExchangeHandler(context);
            case SRP_SHA_DSS:
            case SRP_SHA_RSA:
            case SRP_SHA:
                return new SrpClientKeyExchangeHandler(context);
            case VKO_GOST01:
            case VKO_GOST12:
                return new GOSTClientKeyExchangeHandler(context);
            case ECCPWD:
                return new PWDClientKeyExchangeHandler(context);
            default:
                throw new UnsupportedOperationException("Algorithm " + algorithm + " NOT supported yet.");
        }
    }

    private static HandshakeMessageHandler<? extends HandshakeMessage> getServerKeyExchangeHandler(TlsContext context) {
        // TODO: There should be a server KeyExchangeHandler
        CipherSuite cs = context.getChooser().getSelectedCipherSuite();
        KeyExchangeAlgorithm algorithm = AlgorithmResolver.getKeyExchangeAlgorithm(cs);
        switch (algorithm) {
            case ECDHE_ECDSA:
            case ECDH_ECDSA:
            case ECDH_RSA:
            case ECDHE_RSA:
            case ECDH_ANON:
                return new ECDHEServerKeyExchangeHandler<>(context);
            case DHE_DSS:
            case DHE_RSA:
            case DH_ANON:
            case DH_DSS:
            case DH_RSA:
                return new DHEServerKeyExchangeHandler(context);
            case PSK:
                return new PskServerKeyExchangeHandler(context);
            case DHE_PSK:
                return new PskDheServerKeyExchangeHandler(context);
            case ECDHE_PSK:
                return new PskEcDheServerKeyExchangeHandler(context);
            case SRP_SHA_DSS:
            case SRP_SHA_RSA:
            case SRP_SHA:
                return new SrpServerKeyExchangeHandler(context);
            case ECCPWD:
                return new PWDServerKeyExchangeHandler(context);
            default:
                throw new UnsupportedOperationException("Algorithm " + algorithm + " NOT supported yet.");
        }
    }

    public static ExtensionMessage getExtension(ExtensionType extensionTypeConstant) {
        switch (extensionTypeConstant) {
            case ALPN:
                return new AlpnExtensionMessage();
            case CACHED_INFO:
                return new CachedInfoExtensionMessage();
            case CERTIFICATE_AUTHORITIES:
                LOGGER.warn("CERTIFICATE_AUTHORITIES Extension is no implemented. Returning UNKNOWN_EXTENSION");
                return new UnknownExtensionMessage();
            case CERT_TYPE:
                return new CertificateTypeExtensionMessage();
            case CLIENT_AUTHZ:
                return new ClientAuthzExtensionMessage();
            case CLIENT_CERTIFICATE_TYPE:
                return new ClientCertificateTypeExtensionMessage();
            case CLIENT_CERTIFICATE_URL:
                return new ClientCertificateUrlExtensionMessage();
            case COOKIE:
                return new CookieExtensionMessage();
            case EARLY_DATA:
                return new EarlyDataExtensionMessage();
            case EC_POINT_FORMATS:
                return new ECPointFormatExtensionMessage();
            case ELLIPTIC_CURVES:
                return new EllipticCurvesExtensionMessage();
            case ENCRYPTED_SERVER_NAME_INDICATION:
                return new EncryptedServerNameIndicationExtensionMessage();
            case ENCRYPT_THEN_MAC:
                return new EncryptThenMacExtensionMessage();
            case EXTENDED_MASTER_SECRET:
                return new ExtendedMasterSecretExtensionMessage();
            case EXTENDED_RANDOM:
                return new ExtendedRandomExtensionMessage();
            case GREASE_00:
            case GREASE_01:
            case GREASE_02:
            case GREASE_03:
            case GREASE_04:
            case GREASE_05:
            case GREASE_06:
            case GREASE_07:
            case GREASE_08:
            case GREASE_09:
            case GREASE_10:
            case GREASE_11:
            case GREASE_12:
            case GREASE_13:
            case GREASE_14:
            case GREASE_15:
                return new GreaseExtensionMessage();
            case HEARTBEAT:
                return new HeartbeatExtensionMessage();
            case KEY_SHARE:
                return new KeyShareExtensionMessage();
            case MAX_FRAGMENT_LENGTH:
                return new MaxFragmentLengthExtensionMessage();
            case OID_FILTERS:
                LOGGER.warn("OID_FILTERS Extension is no implemented. Returning UNKNOWN_EXTENSION");
                return new UnknownExtensionMessage();
            case PADDING:
                return new PaddingExtensionMessage();
            case PASSWORD_SALT:
                return new PasswordSaltExtensionMessage();
            case POST_HANDSHAKE_AUTH:
                LOGGER.warn("POST_HANDSHAKE_AUTH Extension is no implemented. Returning UNKNOWN_EXTENSION");
                return new UnknownExtensionMessage();
            case PRE_SHARED_KEY:
                return new PreSharedKeyExtensionMessage();
            case PSK_KEY_EXCHANGE_MODES:
                return new PSKKeyExchangeModesExtensionMessage();
            case PWD_CLEAR:
                return new PWDClearExtensionMessage();
            case PWD_PROTECT:
                return new PWDProtectExtensionMessage();
            case RECORD_SIZE_LIMIT:
                return new RecordSizeLimitExtensionMessage();
            case RENEGOTIATION_INFO:
                return new RenegotiationInfoExtensionMessage();
            case SERVER_AUTHZ:
                return new ServerAuthzExtensionMessage();
            case SERVER_CERTIFICATE_TYPE:
                return new ServerCertificateTypeExtensionMessage();
            case SERVER_NAME_INDICATION:
                return new ServerNameIndicationExtensionMessage();
            case SESSION_TICKET:
                return new SessionTicketTLSExtensionMessage();
            case SIGNATURE_ALGORITHMS_CERT:
                LOGGER.warn("SIGNATURE_ALGORITHMS_CERT Extension is no implemented. Returning UNKNOWN_EXTENSION");
                return new UnknownExtensionMessage();
            case SIGNATURE_AND_HASH_ALGORITHMS:
                return new SignatureAndHashAlgorithmsExtensionMessage();
            case SIGNED_CERTIFICATE_TIMESTAMP:
                return new SignedCertificateTimestampExtensionMessage();
            case SRP:
                return new SRPExtensionMessage();
            case STATUS_REQUEST:
                return new CertificateStatusRequestExtensionMessage();
            case STATUS_REQUEST_V2:
                return new CertificateStatusRequestV2ExtensionMessage();
            case SUPPORTED_VERSIONS:
                return new SupportedVersionsExtensionMessage();
            case TOKEN_BINDING:
                return new TokenBindingExtensionMessage();
            case TRUNCATED_HMAC:
                return new TruncatedHmacExtensionMessage();
            case TRUSTED_CA_KEYS:
                return new TrustedCaIndicationExtensionMessage();
            case UNKNOWN:
                return new UnknownExtensionMessage();
            case USER_MAPPING:
                return new UserMappingExtensionMessage();
            case USE_SRTP:
                return new SRPExtensionMessage();
            default:
                return new UnknownExtensionMessage();
        }
    }

    private HandlerFactory() {
    }
}
