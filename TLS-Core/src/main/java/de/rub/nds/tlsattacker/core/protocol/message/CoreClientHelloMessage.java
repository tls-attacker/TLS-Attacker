/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.*;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class CoreClientHelloMessage<Self extends CoreClientHelloMessage<?>>
        extends HelloMessage<Self> {

    private static final Logger LOGGER = LogManager.getLogger();
    /** compression length */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger compressionLength;
    /** cipher suite byte length */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger cipherSuiteLength;
    /** array of supported CipherSuites */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray cipherSuites;
    /** array of supported compressions */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray compressions;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COOKIE)
    private ModifiableByteArray cookie;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger cookieLength;

    public CoreClientHelloMessage() {
        super(HandshakeMessageType.CLIENT_HELLO);
    }

    public CoreClientHelloMessage(Config tlsConfig) {
        super(HandshakeMessageType.CLIENT_HELLO);
        if (!tlsConfig.getHighestProtocolVersion().isSSL()
                || (tlsConfig.getHighestProtocolVersion().isSSL()
                        && tlsConfig.isAddExtensionsInSSL())) {
            if (tlsConfig.isAddHeartbeatExtension()) {
                addExtension(new HeartbeatExtensionMessage());
            }
            if (tlsConfig.isAddECPointFormatExtension()) {
                addExtension(new ECPointFormatExtensionMessage());
            }
            if (tlsConfig.isAddEllipticCurveExtension()) {
                addExtension(new EllipticCurvesExtensionMessage());
            }
            if (tlsConfig.isAddMaxFragmentLengthExtension()) {
                addExtension(new MaxFragmentLengthExtensionMessage());
            }
            if (tlsConfig.isAddRecordSizeLimitExtension()) {
                addExtension(new RecordSizeLimitExtensionMessage());
            }
            if (tlsConfig.isAddServerNameIndicationExtension()) {
                ServerNameIndicationExtensionMessage extension =
                        new ServerNameIndicationExtensionMessage();
                addExtension(extension);
            }
            if (tlsConfig.isAddEncryptedServerNameIndicationExtension()) {
                EncryptedServerNameIndicationExtensionMessage extensionMessage =
                        new EncryptedServerNameIndicationExtensionMessage();
                byte[] serverName;
                if (tlsConfig.getDefaultClientConnection().getHostname() != null) {
                    serverName =
                            tlsConfig
                                    .getDefaultClientConnection()
                                    .getHostname()
                                    .getBytes(StandardCharsets.US_ASCII);
                } else {
                    LOGGER.warn("SNI not correctly configured!");
                    serverName = new byte[0];
                }
                ServerNamePair pair =
                        new ServerNamePair(tlsConfig.getSniType().getValue(), serverName);
                extensionMessage.getClientEsniInner().getServerNameList().add(pair);
                addExtension(extensionMessage);
            }
            if (tlsConfig.isAddSignatureAndHashAlgorithmsExtension()) {
                addExtension(new SignatureAndHashAlgorithmsExtensionMessage());
            }
            if (tlsConfig.isAddSignatureAlgorithmsCertExtension()) {
                addExtension(new SignatureAlgorithmsCertExtensionMessage());
            }
            if (tlsConfig.isAddSupportedVersionsExtension()) {
                addExtension(new SupportedVersionsExtensionMessage());
            }
            if (tlsConfig.isAddKeyShareExtension()) {
                addExtension(new KeyShareExtensionMessage(tlsConfig));
            }
            if (tlsConfig.isAddEarlyDataExtension()) {
                addExtension(new EarlyDataExtensionMessage());
            }
            if (tlsConfig.isAddPSKKeyExchangeModesExtension()) {
                addExtension(new PSKKeyExchangeModesExtensionMessage(tlsConfig));
            }
            if (tlsConfig.isAddExtendedMasterSecretExtension()) {
                addExtension(new ExtendedMasterSecretExtensionMessage());
            }
            if (tlsConfig.isAddSessionTicketTLSExtension()) {
                addExtension(new SessionTicketTLSExtensionMessage());
            }
            if (tlsConfig.isAddSignedCertificateTimestampExtension()) {
                addExtension(new SignedCertificateTimestampExtensionMessage());
            }
            if (tlsConfig.isAddPaddingExtension()) {
                addExtension(new PaddingExtensionMessage());
            }
            if (tlsConfig.isAddRenegotiationInfoExtension()) {
                addExtension(new RenegotiationInfoExtensionMessage());
            }
            if (tlsConfig.isAddTokenBindingExtension()) {
                addExtension(new TokenBindingExtensionMessage());
            }
            if (tlsConfig.isAddCertificateStatusRequestExtension()) {
                addExtension(new CertificateStatusRequestExtensionMessage());
            }
            if (tlsConfig.isAddAlpnExtension()) {
                addExtension(new AlpnExtensionMessage());
            }
            if (tlsConfig.isAddSRPExtension()) {
                addExtension(new SRPExtensionMessage());
            }
            if (tlsConfig.isAddSRTPExtension()) {
                addExtension(new SrtpExtensionMessage());
            }
            if (tlsConfig.isAddTruncatedHmacExtension()) {
                addExtension(new TruncatedHmacExtensionMessage());
            }
            if (tlsConfig.isAddUserMappingExtension()) {
                addExtension(new UserMappingExtensionMessage());
            }
            if (tlsConfig.isAddCertificateTypeExtension()) {
                addExtension(new CertificateTypeExtensionMessage());
            }
            if (tlsConfig.isAddClientAuthzExtension()) {
                addExtension(new ClientAuthzExtensionMessage());
            }
            if (tlsConfig.isAddServerAuthzExtension()) {
                addExtension(new ServerAuthzExtensionMessage());
            }
            if (tlsConfig.isAddClientCertificateTypeExtension()) {
                addExtension(new ClientCertificateTypeExtensionMessage());
            }
            if (tlsConfig.isAddServerCertificateTypeExtension()) {
                addExtension(new ServerCertificateTypeExtensionMessage());
            }
            if (tlsConfig.isAddEncryptThenMacExtension()) {
                addExtension(new EncryptThenMacExtensionMessage());
            }
            if (tlsConfig.isAddCachedInfoExtension()) {
                addExtension(new CachedInfoExtensionMessage());
            }
            if (tlsConfig.isAddClientCertificateUrlExtension()) {
                addExtension(new ClientCertificateUrlExtensionMessage());
            }
            if (tlsConfig.isAddTrustedCaIndicationExtension()) {
                addExtension(new TrustedCaIndicationExtensionMessage());
            }
            if (tlsConfig.isAddCertificateStatusRequestV2Extension()) {
                addExtension(new CertificateStatusRequestV2ExtensionMessage());
            }
            if (tlsConfig.isAddPWDProtectExtension()) {
                addExtension(new PWDProtectExtensionMessage());
            }
            if (tlsConfig.isAddPWDClearExtension()) {
                addExtension(new PWDClearExtensionMessage());
            }
            if (tlsConfig.isAddExtendedRandomExtension()) {
                addExtension(new ExtendedRandomExtensionMessage());
            }
            if (tlsConfig.isAddCookieExtension()) {
                addExtension(new CookieExtensionMessage());
            }
            if (tlsConfig.isAddConnectionIdExtension()) {
                addExtension(new ConnectionIdExtensionMessage());
            }
            if (tlsConfig.isAddPreSharedKeyExtension()) {
                addExtension(new PreSharedKeyExtensionMessage(tlsConfig));
            }
            // In TLS 1.3, the PSK ext has to be the last ClientHello extension
        }
    }

    public ModifiableInteger getCompressionLength() {
        return compressionLength;
    }

    public ModifiableInteger getCipherSuiteLength() {
        return cipherSuiteLength;
    }

    public ModifiableByteArray getCipherSuites() {
        return cipherSuites;
    }

    public ModifiableByteArray getCompressions() {
        return compressions;
    }

    public void setCompressionLength(ModifiableInteger compressionLength) {
        this.compressionLength = compressionLength;
    }

    public void setCompressionLength(int compressionLength) {
        this.compressionLength =
                ModifiableVariableFactory.safelySetValue(this.compressionLength, compressionLength);
    }

    public void setCipherSuiteLength(ModifiableInteger cipherSuiteLength) {
        this.cipherSuiteLength = cipherSuiteLength;
    }

    public void setCipherSuiteLength(int cipherSuiteLength) {
        this.cipherSuiteLength =
                ModifiableVariableFactory.safelySetValue(this.cipherSuiteLength, cipherSuiteLength);
    }

    public void setCipherSuites(ModifiableByteArray cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    public void setCipherSuites(byte[] array) {
        this.cipherSuites = ModifiableVariableFactory.safelySetValue(cipherSuites, array);
    }

    public void setCompressions(ModifiableByteArray compressions) {
        this.compressions = compressions;
    }

    public void setCompressions(byte[] array) {
        this.compressions = ModifiableVariableFactory.safelySetValue(compressions, array);
    }

    public ModifiableByteArray getCookie() {
        return cookie;
    }

    public ModifiableInteger getCookieLength() {
        return cookieLength;
    }

    public void setCookie(byte[] cookie) {
        this.cookie = ModifiableVariableFactory.safelySetValue(this.cookie, cookie);
    }

    public void setCookie(ModifiableByteArray cookie) {
        this.cookie = cookie;
    }

    public void setCookieLength(int cookieLength) {
        this.cookieLength =
                ModifiableVariableFactory.safelySetValue(this.cookieLength, cookieLength);
    }

    public void setCookieLength(ModifiableInteger cookieLength) {
        this.cookieLength = cookieLength;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("ClientHelloMessage:");
        sb.append("\n  Protocol Version: ");
        if (getProtocolVersion() != null && getProtocolVersion().getValue() != null) {
            sb.append(ProtocolVersion.getProtocolVersion(getProtocolVersion().getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Client Unix Time: ");
        if (getUnixTime() != null && getUnixTime().getValue() != null) {
            sb.append(new Date(ArrayConverter.bytesToLong(getUnixTime().getValue()) * 1000));
        } else {
            sb.append("null");
        }
        sb.append("\n  Client Random: ");
        if (getRandom() != null && getRandom().getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(getRandom().getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Session ID: ");
        if (getSessionId() != null && getSessionId().getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(getSessionId().getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Supported Cipher Suites: ");
        if (getCipherSuites() != null && getCipherSuites().getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(getCipherSuites().getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Supported Compression Methods: ");
        if (getCompressions() != null && getCompressions().getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(getCompressions().getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Extensions: ");
        if (getExtensions() != null) {
            for (ExtensionMessage extension : getExtensions()) {
                sb.append(extension.toString()).append("\n");
            }
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "CH";
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 97 * hash + Objects.hashCode(this.compressionLength);
        hash = 97 * hash + Objects.hashCode(this.cipherSuiteLength);
        hash = 97 * hash + Objects.hashCode(this.cipherSuites);
        hash = 97 * hash + Objects.hashCode(this.compressions);
        hash = 97 * hash + Objects.hashCode(this.cookie);
        hash = 97 * hash + Objects.hashCode(this.cookieLength);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final CoreClientHelloMessage other = (CoreClientHelloMessage) obj;
        if (!Objects.equals(this.compressionLength, other.compressionLength)) {
            return false;
        }
        if (!Objects.equals(this.cipherSuiteLength, other.cipherSuiteLength)) {
            return false;
        }
        if (!Objects.equals(this.cipherSuites, other.cipherSuites)) {
            return false;
        }
        if (!Objects.equals(this.compressions, other.compressions)) {
            return false;
        }
        if (!Objects.equals(this.cookie, other.cookie)) {
            return false;
        }
        return Objects.equals(this.cookieLength, other.cookieLength);
    }
}
