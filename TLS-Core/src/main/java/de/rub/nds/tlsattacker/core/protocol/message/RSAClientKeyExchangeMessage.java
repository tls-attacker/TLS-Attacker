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
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.handler.RSAClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.message.computations.RSAClientComputations;
import de.rub.nds.tlsattacker.core.protocol.parser.RSAClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.RSAClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.RSAClientKeyExchangeSerializer;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.List;

@XmlRootElement(name = "RSAClientKeyExchange")
public class RSAClientKeyExchangeMessage<Self extends RSAClientKeyExchangeMessage<?>>
        extends ClientKeyExchangeMessage<Self> {

    @HoldsModifiableVariable @XmlElement protected RSAClientComputations computations;

    public RSAClientKeyExchangeMessage() {
        super();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("RSAClientKeyExchangeMessage:");
        return sb.toString();
    }

    @Override
    public RSAClientComputations getComputations() {
        return computations;
    }

    @Override
    public RSAClientKeyExchangeHandler getHandler(TlsContext tlsContext) {
        return new RSAClientKeyExchangeHandler<>(tlsContext);
    }

    @Override
    public RSAClientKeyExchangeParser getParser(TlsContext tlsContext, InputStream stream) {
        return new RSAClientKeyExchangeParser<>(stream, tlsContext);
    }

    @Override
    public RSAClientKeyExchangePreparator getPreparator(TlsContext tlsContext) {
        return new RSAClientKeyExchangePreparator(tlsContext.getChooser(), this);
    }

    @Override
    public RSAClientKeyExchangeSerializer getSerializer(TlsContext tlsContext) {
        return new RSAClientKeyExchangeSerializer(
                this, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder();
        sb.append("RSA_CLIENT_KEY_EXCHANGE");
        if (isRetransmission()) {
            sb.append(" (ret.)");
        }
        return sb.toString();
    }

    @Override
    public void prepareComputations() {
        if (computations == null) {
            computations = new RSAClientComputations();
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

    @Override
    public String toShortString() {
        return "RSA_CKE";
    }
}
