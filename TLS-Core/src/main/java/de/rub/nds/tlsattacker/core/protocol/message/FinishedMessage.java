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
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.FinishedHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class FinishedMessage extends HandshakeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.HMAC)
    private ModifiableByteArray verifyData;

    public FinishedMessage(Config tlsConfig) {
        super(tlsConfig, HandshakeMessageType.FINISHED);
    }

    public FinishedMessage() {
        super(HandshakeMessageType.FINISHED);
    }

    public ModifiableByteArray getVerifyData() {
        return verifyData;
    }

    public void setVerifyData(ModifiableByteArray verifyData) {
        this.verifyData = verifyData;
    }

    public void setVerifyData(byte[] value) {
        this.verifyData = ModifiableVariableFactory.safelySetValue(this.verifyData, value);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("FinishedMessage:");
        sb.append("\n  Verify Data: ");
        if (verifyData != null && verifyData.getOriginalValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(verifyData.getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new FinishedHandler(context);
    }
}
