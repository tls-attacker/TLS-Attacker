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
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableHolder;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsattacker.core.protocol.handler.PskServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.message.computations.PSKPremasterComputations;
import de.rub.nds.tlsattacker.core.protocol.parser.PskServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PskServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PskServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.List;

@XmlRootElement(name = "PskServerKeyExchange")
public class PskServerKeyExchangeMessage extends ServerKeyExchangeMessage {

    @HoldsModifiableVariable protected PSKPremasterComputations computations;

    private ModifiableByteArray identityHint;

    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger identityHintLength;

    public PskServerKeyExchangeMessage() {
        super();
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

    public ModifiableInteger getIdentityHintLength() {
        return identityHintLength;
    }

    public void setIdentityHintLength(ModifiableInteger identityHintLength) {
        this.identityHintLength = identityHintLength;
    }

    public void setIdentityHintLength(int identityHintLength) {
        this.identityHintLength =
                ModifiableVariableFactory.safelySetValue(
                        this.identityHintLength, identityHintLength);
    }

    @Override
    public PSKPremasterComputations getKeyExchangeComputations() {
        return computations;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("PskServerKeyExchangeMessage:");
        sb.append("\n  IdentityHintLength: ");
        if (identityHintLength != null && identityHintLength.getValue() != null) {
            sb.append(identityHintLength.getValue());
        } else {
            sb.append("null");
        }
        sb.append("\n  IdentityHint: ");
        if (identityHint != null && identityHint.getValue() != null) {
            sb.append(DataConverter.bytesToHexString(identityHint.getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public PskServerKeyExchangeHandler getHandler(Context context) {
        return new PskServerKeyExchangeHandler(context.getTlsContext());
    }

    @Override
    public PskServerKeyExchangeParser getParser(Context context, InputStream stream) {
        return new PskServerKeyExchangeParser(stream, context.getTlsContext());
    }

    @Override
    public PskServerKeyExchangePreparator getPreparator(Context context) {
        return new PskServerKeyExchangePreparator(context.getChooser(), this);
    }

    @Override
    public PskServerKeyExchangeSerializer getSerializer(Context context) {
        return new PskServerKeyExchangeSerializer(
                this, context.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder();
        sb.append("PSK_SERVER_KEY_EXCHANGE");
        if (isRetransmission()) {
            sb.append(" (ret.)");
        }
        return sb.toString();
    }

    @Override
    public void prepareKeyExchangeComputations() {
        if (getKeyExchangeComputations() == null) {
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

    @Override
    public String toShortString() {
        return "PSK_SKE";
    }
}
