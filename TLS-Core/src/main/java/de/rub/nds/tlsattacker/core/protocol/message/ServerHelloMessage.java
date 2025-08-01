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
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.handler.ServerHelloHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CachedInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestV2ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientAuthzExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateUrlExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ConnectionIdExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CookieExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedRandomExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RecordSizeLimitExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SRPExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerAuthzExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerCertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignedCertificateTimestampExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SrtpExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TruncatedHmacExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TrustedCaIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.UserMappingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.parser.ServerHelloParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ServerHelloPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ServerHelloSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
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
        return Arrays.copyOf(HELLO_RETRY_REQUEST_RANDOM, HELLO_RETRY_REQUEST_RANDOM.length);
    }

    @ModifiableVariableProperty private ModifiableByteArray selectedCipherSuite;

    @ModifiableVariableProperty private ModifiableByte selectedCompressionMethod;

    private Boolean autoSetHelloRetryModeInKeyShare = true;

    private Boolean isHelloRetryRequest = false;

    public ServerHelloMessage(Config tlsConfig) {
        super(HandshakeMessageType.SERVER_HELLO);
        if (!tlsConfig.isRespectClientProposedExtensions()) {
            createConfiguredExtensions(tlsConfig).forEach(this::addExtension);
        }
    }

    public ServerHelloMessage(Config tlsConfig, boolean isHelloRetryRequest) {
        super(HandshakeMessageType.SERVER_HELLO);
        this.isHelloRetryRequest = isHelloRetryRequest;
        if (!tlsConfig.isRespectClientProposedExtensions()) {
            createConfiguredExtensions(tlsConfig).forEach(this::addExtension);
        }
    }

    public ServerHelloMessage() {
        super(HandshakeMessageType.SERVER_HELLO);
    }

    @Override
    public final List<ExtensionMessage> createConfiguredExtensions(Config tlsConfig) {
        List<ExtensionMessage> configuredExtensions = new LinkedList<>();
        if (!tlsConfig.getHighestProtocolVersion().isSSL()
                || (tlsConfig.getHighestProtocolVersion().isSSL()
                        && tlsConfig.isAddExtensionsInSSL())) {
            if (tlsConfig.isAddHeartbeatExtension()) {
                configuredExtensions.add(new HeartbeatExtensionMessage());
            }
            if (tlsConfig.isAddECPointFormatExtension()
                    && !tlsConfig.getHighestProtocolVersion().is13()) {
                configuredExtensions.add(new ECPointFormatExtensionMessage());
            }
            if (tlsConfig.isAddMaxFragmentLengthExtension()) {
                configuredExtensions.add(new MaxFragmentLengthExtensionMessage());
            }
            if (tlsConfig.isAddRecordSizeLimitExtension()
                    && !tlsConfig.getHighestProtocolVersion().is13()) {
                configuredExtensions.add(new RecordSizeLimitExtensionMessage());
            }
            if (tlsConfig.isAddServerNameIndicationExtension()
                    && !tlsConfig.isAddEncryptedClientHelloExtension()
                    && !tlsConfig.isAddEncryptedServerNameIndicationExtension()) {
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
                configuredExtensions.add(extension);
            }
            if (tlsConfig.isAddKeyShareExtension()) {
                configuredExtensions.add(new KeyShareExtensionMessage(tlsConfig));
            }
            if (tlsConfig.isAddEncryptedServerNameIndicationExtension()) {
                configuredExtensions.add(new EncryptedServerNameIndicationExtensionMessage());
            }
            if (tlsConfig.isAddExtendedMasterSecretExtension()) {
                configuredExtensions.add(new ExtendedMasterSecretExtensionMessage());
            }
            if (tlsConfig.isAddSessionTicketTLSExtension()) {
                configuredExtensions.add(new SessionTicketTLSExtensionMessage());
            }
            if (tlsConfig.isAddSignedCertificateTimestampExtension()) {
                configuredExtensions.add(new SignedCertificateTimestampExtensionMessage());
            }
            if (tlsConfig.isAddPaddingExtension()) {
                configuredExtensions.add(new PaddingExtensionMessage());
            }
            if (tlsConfig.isAddRenegotiationInfoExtension()) {
                configuredExtensions.add(new RenegotiationInfoExtensionMessage());
            }
            if (tlsConfig.isAddTokenBindingExtension()) {
                configuredExtensions.add(new TokenBindingExtensionMessage());
            }
            if (tlsConfig.isAddCertificateStatusRequestExtension()) {
                configuredExtensions.add(new CertificateStatusRequestExtensionMessage());
            }
            if (tlsConfig.isAddAlpnExtension()) {
                configuredExtensions.add(new AlpnExtensionMessage());
            }
            if (tlsConfig.isAddSRPExtension()) {
                configuredExtensions.add(new SRPExtensionMessage());
            }
            if (tlsConfig.isAddSRTPExtension()) {
                configuredExtensions.add(new SrtpExtensionMessage());
            }
            if (tlsConfig.isAddTruncatedHmacExtension()) {
                configuredExtensions.add(new TruncatedHmacExtensionMessage());
            }
            if (tlsConfig.isAddUserMappingExtension()) {
                configuredExtensions.add(new UserMappingExtensionMessage());
            }
            if (tlsConfig.isAddCertificateTypeExtension()) {
                configuredExtensions.add(new CertificateTypeExtensionMessage());
            }
            if (tlsConfig.isAddClientAuthzExtension()) {
                configuredExtensions.add(new ClientAuthzExtensionMessage());
            }
            if (tlsConfig.isAddServerAuthzExtension()) {
                configuredExtensions.add(new ServerAuthzExtensionMessage());
            }
            if (tlsConfig.isAddClientCertificateTypeExtension()) {
                configuredExtensions.add(new ClientCertificateTypeExtensionMessage());
            }
            if (tlsConfig.isAddServerCertificateTypeExtension()) {
                configuredExtensions.add(new ServerCertificateTypeExtensionMessage());
            }
            if (tlsConfig.isAddEncryptThenMacExtension()) {
                configuredExtensions.add(new EncryptThenMacExtensionMessage());
            }
            if (tlsConfig.isAddCachedInfoExtension()) {
                configuredExtensions.add(new CachedInfoExtensionMessage());
            }
            if (tlsConfig.isAddClientCertificateUrlExtension()) {
                configuredExtensions.add(new ClientCertificateUrlExtensionMessage());
            }
            if (tlsConfig.isAddTrustedCaIndicationExtension()) {
                configuredExtensions.add(new TrustedCaIndicationExtensionMessage());
            }
            if (tlsConfig.isAddCertificateStatusRequestV2Extension()) {
                configuredExtensions.add(new CertificateStatusRequestV2ExtensionMessage());
            }
            if (tlsConfig.isAddPreSharedKeyExtension()) {
                configuredExtensions.add(new PreSharedKeyExtensionMessage(tlsConfig));
            }
            if (tlsConfig.isAddSupportedVersionsExtension()) {
                configuredExtensions.add(new SupportedVersionsExtensionMessage());
            }
            if (tlsConfig.isAddExtendedRandomExtension()) {
                configuredExtensions.add(new ExtendedRandomExtensionMessage());
            }
            if (tlsConfig.isAddCookieExtension()) {
                configuredExtensions.add(new CookieExtensionMessage());
            }
            if (tlsConfig.isAddConnectionIdExtension()) {
                configuredExtensions.add(new ConnectionIdExtensionMessage());
            }
        }
        return configuredExtensions;
    }

    public Boolean isHelloRetryRequest() {
        return isHelloRetryRequest;
    }

    public void setHelloRetryRequest(Boolean helloRetryRequest) {
        isHelloRetryRequest = helloRetryRequest;
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

    public Boolean hasTls13HelloRetryRequestRandom() {
        if (this.getRandom() != null && this.getRandom().getValue() != null) {
            return Arrays.equals(this.getRandom().getValue(), HELLO_RETRY_REQUEST_RANDOM);
        } else {
            return false;
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
                && !ProtocolVersion.getProtocolVersion(getProtocolVersion().getValue()).is13()) {
            sb.append("\n  Server Unix Time: ")
                    .append(new Date(DataConverter.bytesToLong(getUnixTime().getValue()) * 1000));
        }
        sb.append("\n  Server Unix Time: ");
        if (getProtocolVersion() != null) {
            if (!ProtocolVersion.getProtocolVersion(getProtocolVersion().getValue()).is13()) {
                sb.append(new Date(DataConverter.bytesToLong(getUnixTime().getValue()) * 1000));
            } else {
                sb.append("null");
            }
        } else {
            sb.append("null");
        }
        sb.append("\n  Server Random: ");
        if (getRandom() != null) {
            sb.append(DataConverter.bytesToHexString(getRandom().getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Session ID: ");
        if (getProtocolVersion() != null && getProtocolVersion().getValue() != null) {
            if (!ProtocolVersion.getProtocolVersion(getProtocolVersion().getValue()).is13()) {
                sb.append(DataConverter.bytesToHexString(getSessionId().getValue()));
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
            if (!ProtocolVersion.getProtocolVersion(getProtocolVersion().getValue()).is13()) {
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
    public ServerHelloHandler getHandler(Context context) {
        return new ServerHelloHandler(context.getTlsContext());
    }

    @Override
    public ServerHelloPreparator getPreparator(Context context) {
        return new ServerHelloPreparator(context.getChooser(), this);
    }

    @Override
    public ServerHelloSerializer getSerializer(Context context) {
        return new ServerHelloSerializer(this);
    }

    @Override
    public ServerHelloParser getParser(Context context, InputStream stream) {
        return new ServerHelloParser(stream, context.getTlsContext());
    }

    public Boolean isAutoSetHelloRetryModeInKeyShare() {
        return autoSetHelloRetryModeInKeyShare;
    }

    public void setAutoSetHelloRetryModeInKeyShare(Boolean autoSetHelloRetryModeInKeyShare) {
        this.autoSetHelloRetryModeInKeyShare = autoSetHelloRetryModeInKeyShare;
    }

    public boolean setRetryRequestModeInKeyShare() {
        if (Boolean.TRUE.equals(hasTls13HelloRetryRequestRandom())
                && autoSetHelloRetryModeInKeyShare) {
            return true;
        }
        return false;
    }

    @Override
    public String toCompactString() {
        Boolean isHrr = hasTls13HelloRetryRequestRandom();
        String compactString = super.toCompactString();
        if (isHrr != null && isHrr == true) {
            compactString += "(HRR)";
        }
        return compactString;
    }

    @Override
    public String toShortString() {
        if (hasTls13HelloRetryRequestRandom()) {
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
