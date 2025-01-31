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
import de.rub.nds.tlsattacker.core.protocol.handler.EmptyClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.message.computations.EmptyClientComputations;
import de.rub.nds.tlsattacker.core.protocol.parser.EmptyClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.EmptyClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.EmptyClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.List;

@XmlRootElement(name = "EmptyClientKeyExchange")
public class EmptyClientKeyExchangeMessage extends ClientKeyExchangeMessage {

    @HoldsModifiableVariable protected EmptyClientComputations computations;

    public EmptyClientKeyExchangeMessage() {
        super();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("EmptyClientKeyExchangeMessage:");
        return sb.toString();
    }

    @Override
    public EmptyClientComputations getComputations() {
        return computations;
    }

    @Override
    public EmptyClientKeyExchangeHandler getHandler(Context context) {
        return new EmptyClientKeyExchangeHandler(context.getTlsContext());
    }

    @Override
    public EmptyClientKeyExchangeParser<EmptyClientKeyExchangeMessage> getParser(
            Context context, InputStream stream) {
        return new EmptyClientKeyExchangeParser<>(stream, context.getTlsContext());
    }

    @Override
    public EmptyClientKeyExchangePreparator<EmptyClientKeyExchangeMessage> getPreparator(
            Context context) {
        return new EmptyClientKeyExchangePreparator<>(context.getChooser(), this);
    }

    @Override
    public EmptyClientKeyExchangeSerializer<EmptyClientKeyExchangeMessage> getSerializer(
            Context context) {
        return new EmptyClientKeyExchangeSerializer<>(this);
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder();
        sb.append("EMPTY_CLIENT_KEY_EXCHANGE");
        if (isRetransmission()) {
            sb.append(" (ret.)");
        }
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "E_CKE";
    }

    @Override
    public void prepareComputations() {
        if (getComputations() == null) {
            computations = new EmptyClientComputations();
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
