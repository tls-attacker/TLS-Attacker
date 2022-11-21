/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExtensionParserFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    public static ExtensionParser getExtensionParser(byte[] extensionBytes, int pointer, Config config) {
        if (extensionBytes.length - pointer < ExtensionByteLength.TYPE) {
            throw new ParserException(
                "Could not retrieve Parser for ExtensionBytes. Not Enough bytes left for an ExtensionType");
        }
        byte[] typeBytes = new byte[2];
        typeBytes[0] = extensionBytes[pointer];
        typeBytes[1] = extensionBytes[pointer + 1];
        ExtensionType type = ExtensionType.getExtensionType(typeBytes);
        ExtensionParser parser = null;
        switch (type) {
            case CLIENT_CERTIFICATE_URL:
                parser = new ClientCertificateUrlExtensionParser(pointer, extensionBytes, config);
                break;
            case EC_POINT_FORMATS:
                parser = new ECPointFormatExtensionParser(pointer, extensionBytes, config);
                break;
            case ELLIPTIC_CURVES:
                parser = new EllipticCurvesExtensionParser(pointer, extensionBytes, config);
                break;
            case ENCRYPTED_SERVER_NAME_INDICATION:
                parser = new EncryptedServerNameIndicationExtensionParser(pointer, extensionBytes, config);
                break;
            case HEARTBEAT:
                parser = new HeartbeatExtensionParser(pointer, extensionBytes, config);
                break;
            case MAX_FRAGMENT_LENGTH:
                parser = new MaxFragmentLengthExtensionParser(pointer, extensionBytes, config);
                break;
            case RECORD_SIZE_LIMIT:
                parser = new RecordSizeLimitExtensionParser(pointer, extensionBytes, config);
                break;
            case SERVER_NAME_INDICATION:
                parser = new ServerNameIndicationExtensionParser(pointer, extensionBytes, config);
                break;
            case SIGNATURE_AND_HASH_ALGORITHMS:
                parser = new SignatureAndHashAlgorithmsExtensionParser(pointer, extensionBytes, config);
                break;
            case SIGNATURE_ALGORITHMS_CERT:
                parser = new SignatureAlgorithmsCertExtensionParser(pointer, extensionBytes, config);
                break;
            case SUPPORTED_VERSIONS:
                parser = new SupportedVersionsExtensionParser(pointer, extensionBytes, config);
                break;
            case EXTENDED_RANDOM:
                parser = new ExtendedRandomExtensionParser(pointer, extensionBytes, config);
                break;
            case KEY_SHARE:
                parser = new KeyShareExtensionParser(pointer, extensionBytes, config);
                break;
            case STATUS_REQUEST:
                parser = new CertificateStatusRequestExtensionParser(pointer, extensionBytes, config);
                break;
            case TRUNCATED_HMAC:
                parser = new TruncatedHmacExtensionParser(pointer, extensionBytes, config);
                break;
            case TRUSTED_CA_KEYS:
                parser = new TrustedCaIndicationExtensionParser(pointer, extensionBytes, config);
                break;
            case ALPN:
                parser = new AlpnExtensionParser(pointer, extensionBytes, config);
                break;
            case CACHED_INFO:
                parser = new CachedInfoExtensionParser(pointer, extensionBytes, config);
                break;
            case CERT_TYPE:
                parser = new CertificateTypeExtensionParser(pointer, extensionBytes, config);
                break;
            case CLIENT_AUTHZ:
                parser = new ClientAuthzExtensionParser(pointer, extensionBytes, config);
                break;
            case CLIENT_CERTIFICATE_TYPE:
                parser = new ClientCertificateTypeExtensionParser(pointer, extensionBytes, config);
                break;
            case COOKIE:
                parser = new CookieExtensionParser(pointer, extensionBytes, config);
                break;
            case EARLY_DATA:
                parser = new EarlyDataExtensionParser(pointer, extensionBytes, config);
                break;
            case ENCRYPT_THEN_MAC:
                parser = new EncryptThenMacExtensionParser(pointer, extensionBytes, config);
                break;
            case EXTENDED_MASTER_SECRET:
                parser = new ExtendedMasterSecretExtensionParser(pointer, extensionBytes, config);
                break;
            case PADDING:
                parser = new PaddingExtensionParser(pointer, extensionBytes, config);
                break;
            case PRE_SHARED_KEY:
                parser = new PreSharedKeyExtensionParser(pointer, extensionBytes, config);
                break;
            case PSK_KEY_EXCHANGE_MODES:
                parser = new PSKKeyExchangeModesExtensionParser(pointer, extensionBytes, config);
                break;
            case RENEGOTIATION_INFO:
                parser = new RenegotiationInfoExtensionParser(pointer, extensionBytes, config);
                break;
            case SERVER_AUTHZ:
                parser = new ServerAuthzExtensionParser(pointer, extensionBytes, config);
                break;
            case SERVER_CERTIFICATE_TYPE:
                parser = new ServerCertificateTypeExtensionParser(pointer, extensionBytes, config);
                break;
            case SESSION_TICKET:
                parser = new SessionTicketTLSExtensionParser(pointer, extensionBytes, config);
                break;
            case SIGNED_CERTIFICATE_TIMESTAMP:
                parser = new SignedCertificateTimestampExtensionParser(pointer, extensionBytes, config);
                break;
            case SRP:
                parser = new SRPExtensionParser(pointer, extensionBytes, config);
                break;
            case STATUS_REQUEST_V2:
                parser = new CertificateStatusRequestV2ExtensionParser(pointer, extensionBytes, config);
                break;
            case TOKEN_BINDING:
                parser = new TokenBindingExtensionParser(pointer, extensionBytes, config);
                break;
            case USER_MAPPING:
                parser = new UserMappingExtensionParser(pointer, extensionBytes, config);
                break;
            case USE_SRTP:
                parser = new SrtpExtensionParser(pointer, extensionBytes, config);
                break;
            case PWD_PROTECT:
                parser = new PWDProtectExtensionParser(pointer, extensionBytes, config);
                break;
            case PWD_CLEAR:
                parser = new PWDClearExtensionParser(pointer, extensionBytes, config);
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
                parser = new GreaseExtensionParser(pointer, extensionBytes, config);
                break;
            case UNKNOWN:
                parser = new UnknownExtensionParser(pointer, extensionBytes, config);
                break;
            default:
                parser = new UnknownExtensionParser(pointer, extensionBytes, config);
                break;
        }
        if (parser == null) {
            LOGGER.debug("The ExtensionParser for the " + type.name()
                + " Extension is currently not implemented. Using the UnknownExtensionParser instead");
            parser = new UnknownExtensionParser(pointer, extensionBytes, config);
        }
        return parser;
    }

    private ExtensionParserFactory() {
    }
}
