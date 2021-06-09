/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.handler.HelloRetryRequestHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * As specified in Draft 21 and before
 */
@XmlRootElement
public class HelloRetryRequestMessage extends HandshakeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray protocolVersion;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray selectedCipherSuite;

    public HelloRetryRequestMessage() {
        super(HandshakeMessageType.HELLO_RETRY_REQUEST);
    }

    public HelloRetryRequestMessage(Config tlsConfig) {
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

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("HelloRetryRequestMessage:");
        sb.append("\n  Protocol Version: ");
        if (protocolVersion != null && protocolVersion.getValue() != null) {
            sb.append(ProtocolVersion.getProtocolVersion(protocolVersion.getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Selected Cipher Suite: ");
        if (selectedCipherSuite != null && selectedCipherSuite.getValue() != null) {
            sb.append(CipherSuite.getCipherSuite(selectedCipherSuite.getValue())).append("\n  Extensions: ");
        } else {
            sb.append("null");
        }
        sb.append("\n  Extensions: ");
        if (getExtensions() == null) {
            sb.append("null");
        } else {
            for (ExtensionMessage e : getExtensions()) {
                sb.append("\n  ").append(e.toString());
            }
        }
        return sb.toString();
    }

    @Override
    public HelloRetryRequestHandler getHandler(TlsContext context) {
        return new HelloRetryRequestHandler(context);
    }
}
