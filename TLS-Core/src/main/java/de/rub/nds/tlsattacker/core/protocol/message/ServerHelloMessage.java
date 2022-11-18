/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.ServerHelloHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.*;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.parser.ServerHelloParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ServerHelloPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ServerHelloSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Date;
import java.util.Objects;

@XmlRootElement(name = "ServerHello")
public class ServerHelloMessage extends HelloMessage {

    private static final byte[] HELLO_RETRY_REQUEST_RANDOM =
            new byte[] {
                (byte) 0xCF,
                (byte) 0x21,
                (byte) 0xAD,
                (byte) 0x74,
                (byte) 0xE5,
                (byte) 0x9A,
                (byte) 0x61,
                (byte) 0x11,
                (byte) 0xBE,
                (byte) 0x1D,
                (byte) 0x8C,
                (byte) 0x02,
                (byte) 0x1E,
                (byte) 0x65,
                (byte) 0xB8,
                (byte) 0x91,
                (byte) 0xC2,
                (byte) 0xA2,
                (byte) 0x11,
                (byte) 0x16,
                (byte) 0x7A,
                (byte) 0xBB,
                (byte) 0x8C,
                (byte) 0x5E,
                (byte) 0x07,
                (byte) 0x9E,
                (byte) 0x09,
                (byte) 0xE2,
                (byte) 0xC8,
                (byte) 0xA8,
                (byte) 0x33,
                (byte) 0x9C
            };

    public static byte[] getHelloRetryRequestRandom() {
        return HELLO_RETRY_REQUEST_RANDOM;
    }

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray selectedCipherSuite;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByte selectedCompressionMethod;

    private Boolean autoSetHelloRetryModeInKeyShare = true;

    public ServerHelloMessage(Config tlsConfig) {
        super(HandshakeMessageType.SERVER_HELLO);
        if (!tlsConfig.getHighestProtocolVersion().isSSL()
                || (tlsConfig.getHighestProtocolVersion().isSSL()
                        && tlsConfig.isAddExtensionsInSSL())) {
            if (tlsConfig.isAddHeartbeatExtension()) {
                addExtension(new HeartbeatExtensionMessage());
            }
            if (tlsConfig.isAddECPointFormatExtension()
                    && !(tlsConfig.getHighestProtocolVersion().isTLS13()
                            || tlsConfig.getHighestProtocolVersion() == ProtocolVersion.DTLS13)) {
                addExtension(new ECPointFormatExtensionMessage());
            }
            if (tlsConfig.isAddMaxFragmentLengthExtension()) {
                addExtension(new MaxFragmentLengthExtensionMessage());
            }
            if (tlsConfig.isAddRecordSizeLimitExtension()
                    && !(tlsConfig.getHighestProtocolVersion().isTLS13()
                            || tlsConfig.getHighestProtocolVersion() == ProtocolVersion.DTLS13)) {
                addExtension(new RecordSizeLimitExtensionMessage());
            }
            if (tlsConfig.isAddServerNameIndicationExtension()) {
                ServerNameIndicationExtensionMessage extension =
                        new ServerNameIndicationExtensionMessage();
                ServerNamePair pair =
                        new ServerNamePair(
                                tlsConfig.getSniType().getValue(),
                                tlsConfig
                                        .getDefaultServerConnection()
                                        .getHostname()
                                        .getBytes(Charset.forName("US-ASCII")));
                extension.getServerNameList().add(pair);
                addExtension(extension);
            }

            if (tlsConfig.isAddKeyShareExtension()) {
                addExtension(new KeyShareExtensionMessage(tlsConfig));
            }
            if (tlsConfig.isAddEncryptedServerNameIndicationExtension()) {
                addExtension(new EncryptedServerNameIndicationExtensionMessage());
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
            if (tlsConfig.isAddPreSharedKeyExtension()) {
                addExtension(new PreSharedKeyExtensionMessage(tlsConfig));
            }
            if (tlsConfig.isAddSupportedVersionsExtension()) {
                addExtension(new SupportedVersionsExtensionMessage());
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
        }
    }

    public ServerHelloMessage() {
        super(HandshakeMessageType.SERVER_HELLO);
    }

    public ModifiableByteArray getSelectedCipherSuite() {
        return selectedCipherSuite;
    }

    public void setSelectedCipherSuite(ModifiableByteArray selectedCipherSuite) {
        this.selectedCipherSuite = selectedCipherSuite;
    }

    public void setSelectedCipherSuite(byte[] value) {
        this.selectedCipherSuite =
                ModifiableVariableFactory.safelySetValue(this.selectedCipherSuite, value);
    }

    public ModifiableByte getSelectedCompressionMethod() {
        return selectedCompressionMethod;
    }

    public void setSelectedCompressionMethod(ModifiableByte selectedCompressionMethod) {
        this.selectedCompressionMethod = selectedCompressionMethod;
    }

    public void setSelectedCompressionMethod(byte value) {
        this.selectedCompressionMethod =
                ModifiableVariableFactory.safelySetValue(this.selectedCompressionMethod, value);
    }

    public Boolean isTls13HelloRetryRequest() {
        if (this.getRandom() != null && this.getRandom().getValue() != null) {
            return Arrays.equals(this.getRandom().getValue(), HELLO_RETRY_REQUEST_RANDOM);
        } else {
            return null;
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(super.toString());
        sb.append("\n  Protocol Version: ");
        if (getProtocolVersion() != null) {
            sb.append(ProtocolVersion.getProtocolVersion(getProtocolVersion().getValue()));
        } else {
            sb.append("null");
        }
        if (getProtocolVersion() != null
                && getProtocolVersion().getValue() != null
                && !(ProtocolVersion.getProtocolVersion(getProtocolVersion().getValue()).isTLS13()
                        || ProtocolVersion.getProtocolVersion(getProtocolVersion().getValue())
                                == ProtocolVersion.DTLS13)) {
            sb.append("\n  Server Unix Time: ")
                    .append(new Date(ArrayConverter.bytesToLong(getUnixTime().getValue()) * 1000));
        }
        sb.append("\n  Server Unix Time: ");
        if (getProtocolVersion() != null) {
            if (!(ProtocolVersion.getProtocolVersion(getProtocolVersion().getValue()).isTLS13()
                    || ProtocolVersion.getProtocolVersion(getProtocolVersion().getValue())
                            == ProtocolVersion.DTLS13)) {
                sb.append(new Date(ArrayConverter.bytesToLong(getUnixTime().getValue()) * 1000));
            } else {
                sb.append("null");
            }
        } else {
            sb.append("null");
        }
        sb.append("\n  Server Random: ");
        if (getRandom() != null) {
            sb.append(ArrayConverter.bytesToHexString(getRandom().getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Session ID: ");
        if (getProtocolVersion() != null && getProtocolVersion().getValue() != null) {
            if (!(ProtocolVersion.getProtocolVersion(getProtocolVersion().getValue()).isTLS13()
                    || ProtocolVersion.getProtocolVersion(getProtocolVersion().getValue())
                            == ProtocolVersion.DTLS13)) {
                sb.append(ArrayConverter.bytesToHexString(getSessionId().getValue()));
            } else {
                sb.append("null");
            }
        } else {
            sb.append("null");
        }
        sb.append("\n  Selected Cipher Suite: ");
        if (selectedCipherSuite != null && selectedCipherSuite.getValue() != null) {
            sb.append(CipherSuite.getCipherSuite(selectedCipherSuite.getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Selected Compression Method: ");
        if (getProtocolVersion() != null && getProtocolVersion().getValue() != null) {
            if (!(ProtocolVersion.getProtocolVersion(getProtocolVersion().getValue()).isTLS13()
                    || ProtocolVersion.getProtocolVersion(getProtocolVersion().getValue())
                            == ProtocolVersion.DTLS13)) {
                sb.append(
                        CompressionMethod.getCompressionMethod(
                                selectedCompressionMethod.getValue()));
            } else {
                sb.append("null");
            }
        } else {
            sb.append("null");
        }
        sb.append("\n  Extensions: ");
        if (getExtensions() == null) {
            sb.append("null");
        } else {
            for (ExtensionMessage e : getExtensions()) {
                sb.append(e.toString());
            }
        }
        return sb.toString();
    }

    @Override
    public ServerHelloHandler getHandler(TlsContext tlsContext) {
        return new ServerHelloHandler(tlsContext);
    }

    @Override
    public ServerHelloPreparator getPreparator(TlsContext tlsContext) {
        return new ServerHelloPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public ServerHelloSerializer getSerializer(TlsContext tlsContext) {
        return new ServerHelloSerializer(this);
    }

    @Override
    public ServerHelloParser getParser(TlsContext tlsContext, InputStream stream) {
        return new ServerHelloParser(stream, tlsContext);
    }

    public Boolean isAutoSetHelloRetryModeInKeyShare() {
        return autoSetHelloRetryModeInKeyShare;
    }

    public void setAutoSetHelloRetryModeInKeyShare(Boolean autoSetHelloRetryModeInKeyShare) {
        this.autoSetHelloRetryModeInKeyShare = autoSetHelloRetryModeInKeyShare;
    }

    public boolean setRetryRequestModeInKeyShare() {
        if (Boolean.TRUE.equals(isTls13HelloRetryRequest()) && autoSetHelloRetryModeInKeyShare) {
            return true;
        }
        return false;
    }

    @Override
    public String toCompactString() {
        Boolean isHrr = isTls13HelloRetryRequest();
        String compactString = super.toCompactString();
        if (isHrr != null && isHrr == true) {
            compactString += "(HRR)";
        }
        return compactString;
    }

    @Override
    public String toShortString() {
        if (isTls13HelloRetryRequest()) {
            return "HRR";
        }
        return "SH";
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 89 * hash + Objects.hashCode(this.selectedCipherSuite);
        hash = 89 * hash + Objects.hashCode(this.selectedCompressionMethod);
        hash = 89 * hash + Objects.hashCode(this.autoSetHelloRetryModeInKeyShare);
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
        final ServerHelloMessage other = (ServerHelloMessage) obj;
        if (!Objects.equals(this.selectedCipherSuite, other.selectedCipherSuite)) {
            return false;
        }
        if (!Objects.equals(this.selectedCompressionMethod, other.selectedCompressionMethod)) {
            return false;
        }
        return Objects.equals(
                this.autoSetHelloRetryModeInKeyShare, other.autoSetHelloRetryModeInKeyShare);
    }
}
