/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExtensionParserFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    public static ExtensionParser getExtensionParser(byte[] extensionBytes, int pointer,
            HandshakeMessageType handshakeMessageType) {
        if (extensionBytes.length - pointer < ExtensionByteLength.TYPE) {
            throw new ParserException(
                    "Could not retrieve Parser for ExtensionBytes. Not Enought bytes left for an ExtensionType");
        }
        byte[] typeBytes = new byte[2];
        typeBytes[0] = extensionBytes[pointer];
        typeBytes[1] = extensionBytes[pointer + 1];
        ExtensionType type = ExtensionType.getExtensionType(typeBytes);
        ExtensionParser parser = null;
        switch (type) {
            case CLIENT_CERTIFICATE_URL:
                parser = new ClientCertificateUrlExtensionParser(pointer, extensionBytes);
                break;
            case EC_POINT_FORMATS:
                parser = new ECPointFormatExtensionParser(pointer, extensionBytes);
                break;
            case ELLIPTIC_CURVES:
                parser = new EllipticCurvesExtensionParser(pointer, extensionBytes);
                break;
            case HEARTBEAT:
                parser = new HeartbeatExtensionParser(pointer, extensionBytes);
                break;
            case MAX_FRAGMENT_LENGTH:
                parser = new MaxFragmentLengthExtensionParser(pointer, extensionBytes);
                break;
            case SERVER_NAME_INDICATION:
                parser = new ServerNameIndicationExtensionParser(pointer, extensionBytes);
                break;
            case SIGNATURE_AND_HASH_ALGORITHMS:
                parser = new SignatureAndHashAlgorithmsExtensionParser(pointer, extensionBytes);
                break;
            case SUPPORTED_VERSIONS:
                parser = new SupportedVersionsExtensionParser(pointer, extensionBytes);
                break;
            case KEY_SHARE_OLD: // Extension was moved
            case KEY_SHARE:
                parser = getKeyShareParser(extensionBytes, pointer, handshakeMessageType, type);
                break;
            case STATUS_REQUEST:
                parser = new CertificateStatusRequestExtensionParser(pointer, extensionBytes);
                break;
            case TRUNCATED_HMAC:
                parser = new TruncatedHmacExtensionParser(pointer, extensionBytes);
                break;
            case TRUSTED_CA_KEYS:
                parser = new TrustedCaIndicationExtensionParser(pointer, extensionBytes);
                break;
            case ALPN:
                parser = new AlpnExtensionParser(pointer, extensionBytes);
                break;
            case CACHED_INFO:
                parser = new CachedInfoExtensionParser(pointer, extensionBytes);
                break;
            case CERT_TYPE:
                parser = new CertificateTypeExtensionParser(pointer, extensionBytes);
                break;
            case CLIENT_AUTHZ:
                parser = new ClientAuthzExtensionParser(pointer, extensionBytes);
                break;
            case CLIENT_CERTIFICATE_TYPE:
                parser = new ClientCertificateTypeExtensionParser(pointer, extensionBytes);
                break;
            case EARLY_DATA:
                parser = new EarlyDataExtensionParser(pointer, extensionBytes);
                break;
            case ENCRYPT_THEN_MAC:
                parser = new EncryptThenMacExtensionParser(pointer, extensionBytes);
                break;
            case EXTENDED_MASTER_SECRET:
                parser = new ExtendedMasterSecretExtensionParser(pointer, extensionBytes);
                break;
            case PADDING:
                parser = new PaddingExtensionParser(pointer, extensionBytes);
                break;
            case PRE_SHARED_KEY:
                parser = new PreSharedKeyExtensionParser(pointer, extensionBytes);
                break;
            case PSK_KEY_EXCHANGE_MODES:
                parser = new PSKKeyExchangeModesExtensionParser(pointer, extensionBytes);
                break;
            case RENEGOTIATION_INFO:
                parser = new RenegotiationInfoExtensionParser(pointer, extensionBytes);
                break;
            case SERVER_AUTHZ:
                parser = new ServerAuthzExtensionParser(pointer, extensionBytes);
                break;
            case SERVER_CERTIFICATE_TYPE:
                parser = new ServerCertificateTypeExtensionParser(pointer, extensionBytes);
                break;
            case SESSION_TICKET:
                parser = new SessionTicketTLSExtensionParser(pointer, extensionBytes);
                break;
            case SIGNED_CERTIFICATE_TIMESTAMP:
                parser = new SignedCertificateTimestampExtensionParser(pointer, extensionBytes);
                break;
            case SRP:
                parser = new SRPExtensionParser(pointer, extensionBytes);
                break;
            case STATUS_REQUEST_V2:
                parser = new CertificateStatusRequestV2ExtensionParser(pointer, extensionBytes);
                break;
            case TOKEN_BINDING:
                parser = new TokenBindingExtensionParser(pointer, extensionBytes);
                break;
            case USER_MAPPING:
                parser = new UserMappingExtensionParser(pointer, extensionBytes);
                break;
            case USE_SRTP:
                parser = new SrtpExtensionParser(pointer, extensionBytes);
                break;
            case PWD_PROTECT:
                parser = new PWDProtectExtensionParser(pointer, extensionBytes);
                break;
            case PWD_CLEAR:
                parser = new PWDClearExtensionParser(pointer, extensionBytes);
                break;
            case UNKNOWN:
                parser = new UnknownExtensionParser(pointer, extensionBytes);
                break;
        }
        if (parser == null) {
            LOGGER.debug("The ExtensionParser for the " + type.name()
                    + " Extension is currently not implemented. Using the UnknownExtensionParser instead");
            parser = new UnknownExtensionParser(pointer, extensionBytes);
        }
        return parser;
    }

    private static ExtensionParser getKeyShareParser(byte[] extensionBytes, int pointer, HandshakeMessageType type,
            ExtensionType extensionType) {
        switch (type) {
            case HELLO_RETRY_REQUEST:
                return new HRRKeyShareExtensionParser(pointer, extensionBytes);
            case CLIENT_HELLO:
            case SERVER_HELLO:
                return new KeyShareExtensionParser(pointer, extensionBytes, extensionType);
            default:
                throw new UnsupportedOperationException("KeyShareExtension for following " + type
                        + " message NOT supported yet.");
        }
    }

    private ExtensionParserFactory() {
    }
}
