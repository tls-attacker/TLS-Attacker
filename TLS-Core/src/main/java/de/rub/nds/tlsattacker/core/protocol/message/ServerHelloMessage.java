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
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.handler.ServerHelloHandler;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SNI.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignedCertificateTimestampExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;
import java.util.Date;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
@XmlRootElement
public class ServerHelloMessage extends HelloMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray selectedCipherSuite;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByte selectedCompressionMethod;

    public ServerHelloMessage(TlsConfig tlsConfig) {
        super(tlsConfig, HandshakeMessageType.SERVER_HELLO);
        if (tlsConfig.isAddHeartbeatExtension()) {
            addExtension(new HeartbeatExtensionMessage());
        }
        if (tlsConfig.isAddECPointFormatExtension()) {
            addExtension(new ECPointFormatExtensionMessage());
        }
        if (tlsConfig.isAddEllipticCurveExtension()) {
            addExtension(new EllipticCurvesExtensionMessage());
        }
        if (tlsConfig.isAddMaxFragmentLengthExtenstion()) {
            addExtension(new MaxFragmentLengthExtensionMessage());
        }
        if (tlsConfig.isAddServerNameIndicationExtension()) {
            addExtension(new ServerNameIndicationExtensionMessage());
        }
        if (tlsConfig.isAddSignatureAndHashAlgrorithmsExtension()) {
            addExtension(new SignatureAndHashAlgorithmsExtensionMessage());
        }
        if (tlsConfig.isAddKeyShareExtension() && tlsConfig.getHighestProtocolVersion() == ProtocolVersion.TLS13) {
            addExtension(new KeyShareExtensionMessage());
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
        this.selectedCipherSuite = ModifiableVariableFactory.safelySetValue(this.selectedCipherSuite, value);
    }

    public ModifiableByte getSelectedCompressionMethod() {
        return selectedCompressionMethod;
    }

    public void setSelectedCompressionMethod(ModifiableByte selectedCompressionMethod) {
        this.selectedCompressionMethod = selectedCompressionMethod;
    }

    public void setSelectedCompressionMethod(byte value) {
        this.selectedCompressionMethod = ModifiableVariableFactory
                .safelySetValue(this.selectedCompressionMethod, value);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(super.toString());
        sb.append("\n  Protocol Version: ").append(ProtocolVersion.getProtocolVersion(getProtocolVersion().getValue()));
        if (ProtocolVersion.getProtocolVersion(getProtocolVersion().getValue()) != ProtocolVersion.TLS13) {
            sb.append("\n  Server Unix Time: ").append(
                    new Date(ArrayConverter.bytesToLong(getUnixTime().getValue()) * 1000));
        }
        sb.append("\n  Server Random: ").append(ArrayConverter.bytesToHexString(getRandom().getValue()));
        if (ProtocolVersion.getProtocolVersion(getProtocolVersion().getValue()) != ProtocolVersion.TLS13) {
            sb.append("\n  Session ID: ").append(ArrayConverter.bytesToHexString(getSessionId().getValue()));
        }
        sb.append("\n  Selected Cipher Suite: ").append(CipherSuite.getCipherSuite(selectedCipherSuite.getValue()));
        if (ProtocolVersion.getProtocolVersion(getProtocolVersion().getValue()) != ProtocolVersion.TLS13) {
            sb.append("\n  Selected Compression Method: ").append(
                    CompressionMethod.getCompressionMethod(selectedCompressionMethod.getValue()));
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
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new ServerHelloHandler(context);
    }
}
