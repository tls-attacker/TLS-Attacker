/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.handler.PSKServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.computations.PSKPremasterComputations;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.List;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author Florian Linsner - florian.linsner@rub.de
 */
@XmlRootElement
public class PSKServerKeyExchangeMessage extends ServerKeyExchangeMessage {

    @HoldsModifiableVariable
    protected PSKPremasterComputations computations;

    @ModifiableVariableProperty(format = ModifiableVariableProperty.Format.PKCS1, type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableByteArray identityHint;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableByteArray identityHintLength;

    public PSKServerKeyExchangeMessage() {
        super();
    }

    public PSKServerKeyExchangeMessage(Config tlsConfig) {
        super(tlsConfig, HandshakeMessageType.SERVER_KEY_EXCHANGE);
    }

    public ModifiableByteArray getIdentityHint() {
        return identityHint;
    }

    public void setIdentityHint(ModifiableByteArray identityHint) {
        this.identityHint = identityHint;
    }

    public void setIdentityHint(byte[] identity) {
        this.identityHint = ModifiableVariableFactory.safelySetValue(this.identityHint, identity);
    }

    public ModifiableByteArray getIdentityHintLength() {
        return identityHintLength;
    }

    public void setIdentityHintLength(ModifiableByteArray identity_hint_length) {
        this.identityHintLength = identity_hint_length;
    }

    public void setIdentityHintLength(byte[] identity_hint_length) {
        this.identityHintLength = ModifiableVariableFactory.safelySetValue(this.identityHintLength,
                identity_hint_length);
    }

    @Override
    public PSKPremasterComputations getComputations() {
        return computations;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(super.toString());
        sb.append("\n  IdentityHintLength: ");
        if (identityHintLength != null) {
            sb.append(ArrayConverter.bytesToHexString(identityHintLength.getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  IdentityHint: ");
        if (identityHint != null) {
            sb.append(ArrayConverter.bytesToHexString(identityHint.getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new PSKServerKeyExchangeHandler(context);
    }

    @Override
    public String toCompactString() {
        return "PSK_SERVER_KEY_EXCHANGE";
    }

    @Override
    public void prepareComputations() {
        if (getComputations() == null) {
            computations = new PSKPremasterComputations();
        }
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (computations != null) {
            holders.add(computations);
        }
        return holders;
    }
}
