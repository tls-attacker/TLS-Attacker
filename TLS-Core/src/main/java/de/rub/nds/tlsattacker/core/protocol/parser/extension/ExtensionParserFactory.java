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
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ExtensionParserFactory {

    private static final Logger LOGGER = LogManager.getLogger("ExtensionParserFactory");

    public static ExtensionParser getExtensionParser(byte[] extensionBytes, int pointer) {
        if (extensionBytes.length - pointer < ExtensionByteLength.TYPE) {
            throw new PreparationException("Could not retrieve Parser for ExtensionBytes");
        }
        byte[] typeBytes = new byte[2];
        typeBytes[0] = extensionBytes[pointer];
        typeBytes[1] = extensionBytes[pointer + 1];
        ExtensionType type = ExtensionType.getExtensionType(typeBytes);
        ExtensionParser parser = null;
        switch (type) {
            case CLIENT_CERTIFICATE_URL:
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
            case STATUS_REQUEST:
                parser = new CertificateStatusRequestExtensionParser(pointer, extensionBytes);
                break;
            case TRUNCATED_HMAC:
                break;
            case TRUSTED_CA_KEYS:
                break;
            case ALPN:
                parser = new AlpnExtensionParser(pointer, extensionBytes);
                break;
            case CACHED_INFO:
                break;
            case CERT_TYPE:
                break;
            case CLIENT_AUTHZ:
                break;
            case CLIENT_CERTIFICATE_TYPE:
                break;
            case ENCRYPT_THEN_MAC:
                break;
            case EXTENDED_MASTER_SECRET:
                parser = new ExtendedMasterSecretExtensionParser(pointer, extensionBytes);
                break;
            case PADDING:
                parser = new PaddingExtensionParser(pointer, extensionBytes);
                break;
            case RENEGOTIATION_INFO:
                parser = new RenegotiationInfoExtensionParser(pointer, extensionBytes);
                break;
            case SERVER_AUTHZ:
                break;
            case SERVER_CERTIFICATE_TYPE:
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
                break;
            case TOKEN_BINDING:
                parser = new TokenBindingExtensionParser(pointer, extensionBytes);
                break;
            case USER_MAPPING:
                break;
            case USE_SRTP:
                parser = new SrtpExtensionParser(pointer, extensionBytes);
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

    private ExtensionParserFactory() {
    }
}
