/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExtensionParserFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    public static ExtensionParser getExtensionParser(InputStream stream, ExtensionType type, Config config, ConnectionEndType talkingConnectionEndType, ProtocolVersion selectedVersion) {

        ExtensionParser parser = null;
        switch (type) {
            case CLIENT_CERTIFICATE_URL:
                parser = new ClientCertificateUrlExtensionParser(stream, config);
                break;
            case EC_POINT_FORMATS:
                parser = new ECPointFormatExtensionParser(stream, config);
                break;
            case ELLIPTIC_CURVES:
                parser = new EllipticCurvesExtensionParser(stream, config);
                break;
            case ENCRYPTED_SERVER_NAME_INDICATION:
                parser = new EncryptedServerNameIndicationExtensionParser(stream, config, talkingConnectionEndType);
                break;
            case HEARTBEAT:
                parser = new HeartbeatExtensionParser(stream, config);
                break;
            case MAX_FRAGMENT_LENGTH:
                parser = new MaxFragmentLengthExtensionParser(stream, config);
                break;
            case RECORD_SIZE_LIMIT:
                parser = new RecordSizeLimitExtensionParser(stream, config);
                break;
            case SERVER_NAME_INDICATION:
                parser = new ServerNameIndicationExtensionParser(stream, config);
                break;
            case SIGNATURE_AND_HASH_ALGORITHMS:
                parser = new SignatureAndHashAlgorithmsExtensionParser(stream, config);
                break;
            case SUPPORTED_VERSIONS:
                parser = new SupportedVersionsExtensionParser(stream, config);
                break;
            case EXTENDED_RANDOM:
                parser = new ExtendedRandomExtensionParser(stream, config);
                break;
            case KEY_SHARE:
                parser = new KeyShareExtensionParser(stream, config);
                break;
            case STATUS_REQUEST:
                parser = new CertificateStatusRequestExtensionParser(stream, config, selectedVersion);
                break;
            case TRUNCATED_HMAC:
                parser = new TruncatedHmacExtensionParser(stream, config);
                break;
            case TRUSTED_CA_KEYS:
                parser = new TrustedCaIndicationExtensionParser(stream, config);
                break;
            case ALPN:
                parser = new AlpnExtensionParser(stream, config);
                break;
            case CACHED_INFO:
                parser = new CachedInfoExtensionParser(stream, config);
                break;
            case CERT_TYPE:
                parser = new CertificateTypeExtensionParser(stream, config);
                break;
            case CLIENT_AUTHZ:
                parser = new ClientAuthzExtensionParser(stream, config);
                break;
            case CLIENT_CERTIFICATE_TYPE:
                parser = new ClientCertificateTypeExtensionParser(stream, config);
                break;
            case COOKIE:
                parser = new CookieExtensionParser(stream, config);
                break;
            case EARLY_DATA:
                parser = new EarlyDataExtensionParser(stream, config);
                break;
            case ENCRYPT_THEN_MAC:
                parser = new EncryptThenMacExtensionParser(stream, config);
                break;
            case EXTENDED_MASTER_SECRET:
                parser = new ExtendedMasterSecretExtensionParser(stream, config);
                break;
            case PADDING:
                parser = new PaddingExtensionParser(stream, config);
                break;
            case PRE_SHARED_KEY:
                parser = new PreSharedKeyExtensionParser(stream, config);
                break;
            case PSK_KEY_EXCHANGE_MODES:
                parser = new PSKKeyExchangeModesExtensionParser(stream, config);
                break;
            case RENEGOTIATION_INFO:
                parser = new RenegotiationInfoExtensionParser(stream, config);
                break;
            case SERVER_AUTHZ:
                parser = new ServerAuthzExtensionParser(stream, config);
                break;
            case SERVER_CERTIFICATE_TYPE:
                parser = new ServerCertificateTypeExtensionParser(stream, config);
                break;
            case SESSION_TICKET:
                parser = new SessionTicketTLSExtensionParser(stream, config);
                break;
            case SIGNED_CERTIFICATE_TIMESTAMP:
                parser = new SignedCertificateTimestampExtensionParser(stream, config);
                break;
            case SRP:
                parser = new SRPExtensionParser(stream, config);
                break;
            case STATUS_REQUEST_V2:
                parser = new CertificateStatusRequestV2ExtensionParser(stream, config);
                break;
            case TOKEN_BINDING:
                parser = new TokenBindingExtensionParser(stream, config);
                break;
            case USER_MAPPING:
                parser = new UserMappingExtensionParser(stream, config);
                break;
            case USE_SRTP:
                parser = new SrtpExtensionParser(stream, config);
                break;
            case PWD_PROTECT:
                parser = new PWDProtectExtensionParser(stream, config);
                break;
            case PWD_CLEAR:
                parser = new PWDClearExtensionParser(stream, config);
                break;
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
                parser = new GreaseExtensionParser(stream, config);
                break;
            case UNKNOWN:
                parser = new UnknownExtensionParser(stream, config);
                break;
            default:
                parser = new UnknownExtensionParser(stream, config);
                break;
        }
        if (parser == null) {
            LOGGER.warn("The ExtensionParser for the " + type.name()
                    + " Extension is currently not implemented. Using the UnknownExtensionParser instead");
            parser = new UnknownExtensionParser(stream, config);
        }
        return parser;
    }

    private ExtensionParserFactory() {
    }
}
