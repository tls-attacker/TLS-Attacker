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
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.ChangeCipherSpecHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class ChangeCipherSpecMessage extends ProtocolMessage {

    @ModifiableVariableProperty
    ModifiableByte ccsProtocolType;

    public ChangeCipherSpecMessage(Config tlsConfig) {
        super();
        this.protocolMessageType = ProtocolMessageType.CHANGE_CIPHER_SPEC;
    }

    public ChangeCipherSpecMessage() {
        super();
        this.protocolMessageType = ProtocolMessageType.CHANGE_CIPHER_SPEC;
    }

    public ModifiableByte getCcsProtocolType() {
        return ccsProtocolType;
    }

    public void setCcsProtocolType(ModifiableByte ccsProtocolType) {
        this.ccsProtocolType = ccsProtocolType;
    }

    public void setCcsProtocolType(byte value) {
        this.ccsProtocolType = ModifiableVariableFactory.safelySetValue(ccsProtocolType, value);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("ChangeCipherSpecMessage:");
        sb.append("\n  CCS ProtocolType: ");
        if (ccsProtocolType != null && ccsProtocolType.getValue() != null) {
            sb.append(String.format("%02X ", ccsProtocolType.getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public String toCompactString() {
        return "CHANGE_CIPHER_SPEC";
    }

    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new ChangeCipherSpecHandler(context);
    }
}
