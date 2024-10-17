/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.handler.DHClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.message.computations.DHClientComputations;
import de.rub.nds.tlsattacker.core.protocol.parser.DHClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.DHClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.DHClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.List;

@XmlRootElement(name = "DHClientKeyExchange")
public class DHClientKeyExchangeMessage extends ClientKeyExchangeMessage {

    @HoldsModifiableVariable protected DHClientComputations computations;

    public DHClientKeyExchangeMessage() {
        super();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("DHClientKeyExchangeMessage:");
        return sb.toString();
    }

    @Override
    public DHClientComputations getComputations() {
        return computations;
    }

    @Override
    public DHClientKeyExchangeHandler<? extends DHClientKeyExchangeMessage> getHandler(
            Context context) {
        return new DHClientKeyExchangeHandler<>(context.getTlsContext());
    }

    @Override
    public DHClientKeyExchangeParser<? extends DHClientKeyExchangeMessage> getParser(
            Context context, InputStream stream) {
        return new DHClientKeyExchangeParser<>(stream, context.getTlsContext());
    }

    @Override
    public DHClientKeyExchangePreparator<? extends DHClientKeyExchangeMessage> getPreparator(
            Context context) {
        return new DHClientKeyExchangePreparator<>(context.getTlsContext().getChooser(), this);
    }

    @Override
    public DHClientKeyExchangeSerializer<? extends DHClientKeyExchangeMessage> getSerializer(
            Context context) {
        return new DHClientKeyExchangeSerializer<>(this);
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder();
        sb.append("DH_CLIENT_KEY_EXCHANGE");
        if (isRetransmission()) {
            sb.append(" (ret.)");
        }
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "DH_CKE";
    }

    @Override
    public void prepareComputations() {
        if (getComputations() == null) {
            computations = new DHClientComputations();
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
