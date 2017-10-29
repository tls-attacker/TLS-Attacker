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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.PSKRSAClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.message.computations.PSKRSAPremasterComputations;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.util.ArrayConverter;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
@XmlRootElement
public class PSKRSAClientKeyExchangeMessage extends ClientKeyExchangeMessage {

    @HoldsModifiableVariable
    @XmlElement
    protected PSKRSAPremasterComputations computations;

    @HoldsModifiableVariable
    @XmlElement
    @ModifiableVariableProperty(format = ModifiableVariableProperty.Format.PKCS1, type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableByteArray identity;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableByteArray identityLength;

    public PSKRSAClientKeyExchangeMessage(Config tlsConfig) {
        super(tlsConfig);
    }

    public PSKRSAClientKeyExchangeMessage() {
        super();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\nPSK RSA Client Key Exchange message:");
        if (identityLength != null) {
            sb.append("\nPSKIdentity Length:");
            sb.append(identityLength.getValue());
        }
        if (identity != null) {
            sb.append("\nPSKIdentity:");
            sb.append(ArrayConverter.bytesToHexString(identity.getValue()));
        }
        return sb.toString();
    }

    @Override
    public PSKRSAPremasterComputations getComputations() {
        return computations;
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

    public ModifiableByteArray getIdentityLength() {
        return identityLength;
    }

    public void setIdentityLength(ModifiableByteArray identity_length) {
        this.identityLength = identity_length;
    }

    public void setIdentityLength(byte[] identity_length) {
        this.identityLength = ModifiableVariableFactory.safelySetValue(this.identityLength, identity_length);
    }

    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new PSKRSAClientKeyExchangeHandler(context);
    }

    @Override
    public String toCompactString() {
        return "PSK_RSA_CLIENT_KEY_EXCHANGE";
    }

    @Override
    public void prepareComputations() {
        if (computations == null) {
            computations = new PSKRSAPremasterComputations();
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
