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
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.PskDhClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class PskDhClientKeyExchangeMessage extends DHClientKeyExchangeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableByteArray identity;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger identityLength;

    public PskDhClientKeyExchangeMessage(Config tlsConfig) {
        super(tlsConfig);
    }

    public PskDhClientKeyExchangeMessage() {
        super();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("PskDhClientKeyExchangeMessage:");
        sb.append("\n  PSKIdentity Length: ");
        if (identityLength != null && identityLength.getValue() != null) {
            sb.append(identityLength.getValue());
        } else {
            sb.append("null");
        }
        sb.append("\n  PSKIdentity: ");
        if (identity != null && identity.getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(identity.getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    public ModifiableByteArray getIdentity() {
        return identity;
    }

    public void setIdentity(ModifiableByteArray identity) {
        this.identity = identity;
    }

    public void setIdentity(byte[] identity) {
        this.identity = ModifiableVariableFactory.safelySetValue(this.identity, identity);
    }

    public ModifiableInteger getIdentityLength() {
        return identityLength;
    }

    public void setIdentityLength(ModifiableInteger identityLength) {
        this.identityLength = identityLength;
    }

    public void setIdentityLength(int identityLength) {
        this.identityLength = ModifiableVariableFactory.safelySetValue(this.identityLength, identityLength);
    }

    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new PskDhClientKeyExchangeHandler(context);
    }

    @Override
    public String toCompactString() {
        return "PSK_DH_CLIENT_KEY_EXCHANGE";
    }
}
