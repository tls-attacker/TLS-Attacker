/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.handler.ClientHelloHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.*;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.nio.charset.Charset;
import java.util.Date;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class ClientHelloMessage extends HelloMessage {

    /**
     * compression length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger compressionLength;
    /**
     * cipher suite byte length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger cipherSuiteLength;
    /**
     * array of supported CipherSuites
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray cipherSuites;
    /**
     * array of supported compressions
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray compressions;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COOKIE)
    private ModifiableByteArray cookie = null;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableByte cookieLength = null;

    public ClientHelloMessage() {
        super(HandshakeMessageType.CLIENT_HELLO);
    }

    public ClientHelloMessage(Config tlsConfig) {
        super(tlsConfig, HandshakeMessageType.CLIENT_HELLO);
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
        if (tlsConfig.isAddServerNameIndicationExtension()) {
            ServerNameIndicationExtensionMessage extension = new ServerNameIndicationExtensionMessage();
            ServerNamePair pair = new ServerNamePair();
            pair.setServerNameConfig(tlsConfig.getDefaultClientConnection().getHostname()
                    .getBytes(Charset.forName("ASCII")));
            pair.setServerNameTypeConfig(tlsConfig.getSniType().getValue());
            extension.getServerNameList().add(pair);
            addExtension(extension);
        }
        if (tlsConfig.isAddSignatureAndHashAlgrorithmsExtension()) {
            addExtension(new SignatureAndHashAlgorithmsExtensionMessage());
        }
        if (tlsConfig.isAddSupportedVersionsExtension()) {
            addExtension(new SupportedVersionsExtensionMessage());
        }
        if (tlsConfig.isAddKeyShareExtension()) {
            if (tlsConfig.getHighestProtocolVersion() != ProtocolVersion.TLS13
                    && tlsConfig.getHighestProtocolVersion().getMinor() < 0x17) {
                addExtension(new DraftKeyShareExtensionMessage(tlsConfig));
            } else {
                addExtension(new KeyShareExtensionMessage(tlsConfig));
            }
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
            addExtension(new AlpnExtensionMessage(tlsConfig));
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
        if (tlsConfig.isAddPreSharedKeyExtension()) {
            addExtension(new PreSharedKeyExtensionMessage(tlsConfig));
        }
        // In TLS 1.3, the PSK ext has to be the last ClientHello extension
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

    public void setCipherSuiteLength(ModifiableInteger cipherSuiteLength) {
        this.cipherSuiteLength = cipherSuiteLength;
    }

    public void setCipherSuites(ModifiableByteArray cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    public void setCompressions(ModifiableByteArray compressions) {
        this.compressions = compressions;
    }

    public void setCompressionLength(int compressionLength) {
        this.compressionLength = ModifiableVariableFactory.safelySetValue(this.compressionLength, compressionLength);
    }

    public void setCipherSuiteLength(int cipherSuiteLength) {
        this.cipherSuiteLength = ModifiableVariableFactory.safelySetValue(this.cipherSuiteLength, cipherSuiteLength);
    }

    public void setCipherSuites(byte[] array) {
        this.cipherSuites = ModifiableVariableFactory.safelySetValue(cipherSuites, array);
    }

    public void setCompressions(byte[] array) {
        this.compressions = ModifiableVariableFactory.safelySetValue(compressions, array);
    }

    public ModifiableByteArray getCookie() {
        return cookie;
    }

    public ModifiableByte getCookieLength() {
        return cookieLength;
    }

    public void setCookie(byte[] cookie) {
        this.cookie = ModifiableVariableFactory.safelySetValue(this.cookie, cookie);
    }

    public void setCookie(ModifiableByteArray cookie) {
        this.cookie = cookie;
    }

    public void setCookieLength(byte cookieLength) {
        this.cookieLength = ModifiableVariableFactory.safelySetValue(this.cookieLength, cookieLength);
    }

    public void setCookieLength(ModifiableByte cookieLength) {
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
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new ClientHelloHandler(context);
    }

}
