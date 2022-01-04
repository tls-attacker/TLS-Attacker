/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.factory;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.handler.*;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.*;
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
