/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
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
import de.rub.nds.tlsattacker.core.protocol.message.extension.SrtpExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TruncatedHmacExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TrustedCaIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.UnknownExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.UserMappingExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExtensionFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    public static ExtensionMessage getExtension(ExtensionType type) {
        switch (type) {
            case CLIENT_CERTIFICATE_URL:
                return new ClientCertificateUrlExtensionMessage();
            case EC_POINT_FORMATS:
                return new ECPointFormatExtensionMessage();
            case ELLIPTIC_CURVES:
                return new EllipticCurvesExtensionMessage();
            case ENCRYPTED_SERVER_NAME_INDICATION:
                return new EncryptedServerNameIndicationExtensionMessage();
            case HEARTBEAT:
                return new HeartbeatExtensionMessage();
            case MAX_FRAGMENT_LENGTH:
                return new MaxFragmentLengthExtensionMessage();
            case RECORD_SIZE_LIMIT:
                return new RecordSizeLimitExtensionMessage();
            case SERVER_NAME_INDICATION:
                return new ServerNameIndicationExtensionMessage();
            case SIGNATURE_AND_HASH_ALGORITHMS:
                return new SignatureAndHashAlgorithmsExtensionMessage();
            case SUPPORTED_VERSIONS:
                return new SupportedVersionsExtensionMessage();
            case EXTENDED_RANDOM:
                return new ExtendedRandomExtensionMessage();
            case KEY_SHARE:
                return new KeyShareExtensionMessage();
            case STATUS_REQUEST:
                return new CertificateStatusRequestExtensionMessage();
            case TRUNCATED_HMAC:
                return new TruncatedHmacExtensionMessage();
            case TRUSTED_CA_KEYS:
                return new TrustedCaIndicationExtensionMessage();
            case ALPN:
                return new AlpnExtensionMessage();
            case CACHED_INFO:
                return new CachedInfoExtensionMessage();
            case CERT_TYPE:
                return new CertificateTypeExtensionMessage();
            case CLIENT_AUTHZ:
                return new ClientAuthzExtensionMessage();
            case CLIENT_CERTIFICATE_TYPE:
                return new ClientCertificateTypeExtensionMessage();
            case COOKIE:
                return new CookieExtensionMessage();
            case EARLY_DATA:
                return new EarlyDataExtensionMessage();
            case ENCRYPT_THEN_MAC:
                return new EncryptThenMacExtensionMessage();
            case EXTENDED_MASTER_SECRET:
                return new ExtendedMasterSecretExtensionMessage();
            case PADDING:
                return new PaddingExtensionMessage();
            case PRE_SHARED_KEY:
                return new PreSharedKeyExtensionMessage();
            case PSK_KEY_EXCHANGE_MODES:
                return new PSKKeyExchangeModesExtensionMessage();
            case RENEGOTIATION_INFO:
                return new RenegotiationInfoExtensionMessage();
            case SERVER_AUTHZ:
                return new ServerAuthzExtensionMessage();
            case SERVER_CERTIFICATE_TYPE:
                return new ServerCertificateTypeExtensionMessage();
            case SESSION_TICKET:
                return new SessionTicketTLSExtensionMessage();
            case SIGNED_CERTIFICATE_TIMESTAMP:
                return new SignedCertificateTimestampExtensionMessage();
            case SRP:
                return new SRPExtensionMessage();
            case STATUS_REQUEST_V2:
                return new CertificateStatusRequestV2ExtensionMessage();
            case TOKEN_BINDING:
                return new TokenBindingExtensionMessage();
            case USER_MAPPING:
                return new UserMappingExtensionMessage();
            case USE_SRTP:
                return new SrtpExtensionMessage();
            case PWD_PROTECT:
                return new PWDProtectExtensionMessage();
            case PWD_CLEAR:
                return new PWDClearExtensionMessage();
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
            case UNKNOWN:
                return new UnknownExtensionMessage();
            default:
                return new UnknownExtensionMessage();
        }
    }

    private ExtensionFactory() {
    }
}
