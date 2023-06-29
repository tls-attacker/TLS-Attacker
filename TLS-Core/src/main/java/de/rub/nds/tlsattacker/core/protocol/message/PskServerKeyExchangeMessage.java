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
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.handler.PskServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.message.computations.PSKPremasterComputations;
import de.rub.nds.tlsattacker.core.protocol.parser.PskServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PskServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PskServerKeyExchangeSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.List;

@XmlRootElement(name = "PskServerKeyExchange")
public class PskServerKeyExchangeMessage
        extends ServerKeyExchangeMessage<PskServerKeyExchangeMessage> {

    @HoldsModifiableVariable protected PSKPremasterComputations computations;

    private ModifiableByteArray identityHint;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
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
    public PSKPremasterComputations getComputations() {
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
            sb.append(ArrayConverter.bytesToHexString(identityHint.getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public PskServerKeyExchangeHandler getHandler(TlsContext tlsContext) {
        return new PskServerKeyExchangeHandler(tlsContext);
    }

    @Override
    public PskServerKeyExchangeParser getParser(TlsContext tlsContext, InputStream stream) {
        return new PskServerKeyExchangeParser(stream, tlsContext);
    }

    @Override
    public PskServerKeyExchangePreparator getPreparator(TlsContext tlsContext) {
        return new PskServerKeyExchangePreparator(tlsContext.getChooser(), this);
    }

    @Override
    public PskServerKeyExchangeSerializer getSerializer(TlsContext tlsContext) {
        return new PskServerKeyExchangeSerializer(
                this, tlsContext.getChooser().getSelectedProtocolVersion());
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

    @Override
    public String toShortString() {
        return "PSK_SKE";
    }
}
