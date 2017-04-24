/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.message;

import de.rub.nds.tlsattacker.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.handler.HelloRetryRequestHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Nurullah Erinola
 */
public class HelloRetryRequestMessage extends HandshakeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray protocolVersion;
    
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray selectedCipherSuite;
    
    @HoldsModifiableVariable
    private List<ExtensionMessage> extensions;

    @ModifiableVariableProperty
    private ModifiableByteArray extensionBytes;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger extensionsLength;
    
    public HelloRetryRequestMessage() {
        super(HandshakeMessageType.HELLO_RETRY_REQUEST);
    }
    
    public HelloRetryRequestMessage(TlsConfig tlsConfig) {
        super(tlsConfig, HandshakeMessageType.HELLO_RETRY_REQUEST);
    }

    public ModifiableByteArray getProtocolVersion() {
        return protocolVersion;
    }

    public void setProtocolVersion(ModifiableByteArray protocolVersion) {
        this.protocolVersion = protocolVersion;
    }
    
    public void setProtocolVersion(byte[] array) {
        this.protocolVersion = ModifiableVariableFactory.safelySetValue(this.protocolVersion, array);
    }
    
    public ModifiableByteArray getSelectedCipherSuite() {
        return selectedCipherSuite;
    }

    public void setSelectedCipherSuite(ModifiableByteArray cipherSuite) {
        this.selectedCipherSuite = cipherSuite;
    }

    public void setSelectedCipherSuite(byte[] value) {
        this.selectedCipherSuite = ModifiableVariableFactory.safelySetValue(this.selectedCipherSuite, value);
    }
    
    public ModifiableInteger getExtensionsLength() {
        return extensionsLength;
    }

    public void setExtensionsLength(ModifiableInteger extensionsLength) {
        this.extensionsLength = extensionsLength;
    }

    public void setExtensionsLength(int extensionsLength) {
        this.extensionsLength = ModifiableVariableFactory.safelySetValue(this.extensionsLength, extensionsLength);
    }
    
    public ModifiableByteArray getExtensionBytes() {
        return extensionBytes;
    }
    
    public void setExtensionBytes(byte[] extensionBytes) {
        this.extensionBytes = ModifiableVariableFactory.safelySetValue(this.extensionBytes, extensionBytes);
    }
    
    public void setExtensionBytes(ModifiableByteArray extensionBytes) {
        this.extensionBytes = extensionBytes;
    }
        
    public List<ExtensionMessage> getExtensions() {
        return extensions;
    }

    public void setExtensions(List<ExtensionMessage> extensions) {
        this.extensions = extensions;
    }

    public void addExtension(ExtensionMessage extension) {
        if (this.extensions == null) {
            extensions = new LinkedList<>();
        }
        this.extensions.add(extension);
    }

    public boolean containsExtension(ExtensionType extensionType) {
        for (ExtensionMessage e : extensions) {
            if (e.getExtensionTypeConstant() == extensionType) {
                return true;
            }
        }
        return false;
    }
    
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(super.toString());
        sb.append("\n  Protocol Version: ").append(ProtocolVersion.getProtocolVersion(protocolVersion.getValue()))
                .append("\n  Selected Cipher Suite: ")
                .append(CipherSuite.getCipherSuite(selectedCipherSuite.getValue()))
                .append("\n  Extensions: ");
        if (extensions == null) {
            sb.append("null");
        } else {
            for (ExtensionMessage e : extensions) {
                sb.append(e.toString());
            }
        }
        return sb.toString();
    }
    
    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new HelloRetryRequestHandler(context);
    }
}
