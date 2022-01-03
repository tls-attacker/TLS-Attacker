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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.handler.ECDHClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.message.computations.ECDHClientComputations;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.List;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "ECDHClientKeyExchange")
public class ECDHClientKeyExchangeMessage extends ClientKeyExchangeMessage {

    @HoldsModifiableVariable
    protected ECDHClientComputations computations;

    public ECDHClientKeyExchangeMessage() {
        super();
    }

    public ECDHClientKeyExchangeMessage(Config tlsConfig) {
        super(tlsConfig);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("ECDHClientKeyExchangeMessage:");
        return sb.toString();
    }

    @Override
    public ECDHClientComputations getComputations() {
        return computations;
    }

    @Override
    public ECDHClientKeyExchangeHandler<? extends ECDHClientKeyExchangeMessage> getHandler(TlsContext context) {
        return new ECDHClientKeyExchangeHandler<>(context);
    }

    @Override
    public String toCompactString() {
        return "ECDH_CLIENT_KEY_EXCHANGE";
    }

    @Override
    public String toShortString() {
        return "ECDH_CKE";
    }

    @Override
    public void prepareComputations() {
        if (computations == null) {
            computations = new ECDHClientComputations();
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
