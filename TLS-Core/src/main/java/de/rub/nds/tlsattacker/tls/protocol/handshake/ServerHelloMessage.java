/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.tls.protocol.handshake.handler.ServerHelloHandler;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Date;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ServerHelloMessage extends HelloMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray selectedCipherSuite;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByte selectedCompressionMethod;

    public ServerHelloMessage(TlsConfig tlsConfig) {
        super(tlsConfig, HandshakeMessageType.SERVER_HELLO);
        if (tlsConfig.isAddHeartbeatExtension()) {
            addExtension(new HeartbeatExtensionMessage(tlsConfig));
        }
        if (tlsConfig.isAddECPointFormatExtension()) {
            addExtension(new ECPointFormatExtensionMessage(tlsConfig));
        }
        if (tlsConfig.isAddEllipticCurveExtension()) {
            addExtension(new EllipticCurvesExtensionMessage(tlsConfig));
        }
        if (tlsConfig.isAddMaxFragmentLengthExtenstion()) {
            addExtension(new MaxFragmentLengthExtensionMessage(tlsConfig));
        }
        if (tlsConfig.isAddServerNameIndicationExtension()) {
            addExtension(new ServerNameIndicationExtensionMessage(tlsConfig));
        }
        if (tlsConfig.isAddSignatureAndHashAlgrorithmsExtension()) {
            addExtension(new SignatureAndHashAlgorithmsExtensionMessage(tlsConfig));
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
        StringBuilder sb = new StringBuilder();
        sb.append(super.toString()).append("\n  Protocol Version: ")
                .append(ProtocolVersion.getProtocolVersion(getProtocolVersion().getValue()))
                .append("\n  Server Unix Time: ")
                .append(new Date(ArrayConverter.bytesToLong(getUnixTime().getValue()) * 1000))
                .append("\n  Server Random: ").append(ArrayConverter.bytesToHexString(getRandom().getValue()))
                .append("\n  Session ID: ").append(ArrayConverter.bytesToHexString(getSessionId().getValue()))
                .append("\n  Selected Cipher Suite: ")
                .append(CipherSuite.getCipherSuite(selectedCipherSuite.getValue()))
                .append("\n  Selected Compression Method: ")
                .append(CompressionMethod.getCompressionMethod(selectedCompressionMethod.getValue()))
                .append("\n  Extensions: ");
        for (ExtensionMessage e : getExtensions()) {
            sb.append(e.toString());
        }
        return sb.toString();
    }

    @Override
    public ProtocolMessageHandler getProtocolMessageHandler(TlsContext tlsContext) {
        ProtocolMessageHandler handler = new ServerHelloHandler(tlsContext);
        handler.setProtocolMessage(this);
        return handler;
    }
}
