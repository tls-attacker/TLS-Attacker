/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.handler.GOSTClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.message.computations.GOSTClientComputations;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "GOSTClientKeyExchange")
public class GOSTClientKeyExchangeMessage extends ClientKeyExchangeMessage {

    @HoldsModifiableVariable
    @XmlElement
    protected GOSTClientComputations computations;

    @ModifiableVariableProperty(format = ModifiableVariableProperty.Format.ASN1,
        type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    private ModifiableByteArray keyTransportBlob;

    public GOSTClientKeyExchangeMessage() {
        super();
    }

    public GOSTClientKeyExchangeMessage(Config tlsConfig) {
        super(tlsConfig);
    }

    public void setKeyTransportBlob(ModifiableByteArray keyTransportBlob) {
        this.keyTransportBlob = keyTransportBlob;
    }

    public void setKeyTransportBlob(byte[] keyTransportBlob) {
        this.keyTransportBlob = ModifiableVariableFactory.safelySetValue(this.keyTransportBlob, keyTransportBlob);
    }

    public ModifiableByteArray getKeyTransportBlob() {
        return keyTransportBlob;
    }

    @Override
    public GOSTClientComputations getComputations() {
        return computations;
    }

    @Override
    public void prepareComputations() {
        if (computations == null) {
            computations = new GOSTClientComputations();
        }
    }

    @Override
    public String toCompactString() {
        return "GOST_CLIENT_KEY_EXCHANGE";
    }

    @Override
    public GOSTClientKeyExchangeHandler getHandler(TlsContext context) {
        return new GOSTClientKeyExchangeHandler(context);
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (computations != null) {
            holders.add(computations);
        }
        return holders;
    }

    @Override
    public String toShortString() {
        return "GOST_CKE";
    }

}
