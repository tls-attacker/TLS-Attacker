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
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.handler.GOSTClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.message.computations.GOSTClientComputations;
import de.rub.nds.tlsattacker.core.protocol.parser.GOSTClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.GOST01ClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.GOST12ClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.GOSTClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.GOSTClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.List;

@XmlRootElement(name = "GOSTClientKeyExchange")
public class GOSTClientKeyExchangeMessage extends ClientKeyExchangeMessage {

    @HoldsModifiableVariable @XmlElement protected GOSTClientComputations computations;

    @ModifiableVariableProperty(
            format = ModifiableVariableProperty.Format.ASN1,
            type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    private ModifiableByteArray keyTransportBlob;

    public GOSTClientKeyExchangeMessage() {
        super();
    }

    public void setKeyTransportBlob(ModifiableByteArray keyTransportBlob) {
        this.keyTransportBlob = keyTransportBlob;
    }

    public void setKeyTransportBlob(byte[] keyTransportBlob) {
        this.keyTransportBlob =
                ModifiableVariableFactory.safelySetValue(this.keyTransportBlob, keyTransportBlob);
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
        StringBuilder sb = new StringBuilder();
        sb.append("GOST_CLIENT_KEY_EXCHANGE");
        if (isRetransmission()) {
            sb.append(" (ret.)");
        }
        return sb.toString();
    }

    @Override
    public GOSTClientKeyExchangeHandler getHandler(Context context) {
        return new GOSTClientKeyExchangeHandler(context.getTlsContext());
    }

    @Override
    public GOSTClientKeyExchangeParser getParser(Context context, InputStream stream) {
        return new GOSTClientKeyExchangeParser(stream, context.getTlsContext());
    }

    @Override
    public GOSTClientKeyExchangePreparator getPreparator(Context context) {
        CipherSuite cipherSuite = context.getChooser().getSelectedCipherSuite();
        KeyExchangeAlgorithm exchangeAlg = AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite);
        if (exchangeAlg == KeyExchangeAlgorithm.VKO_GOST12) {
            return new GOST12ClientKeyExchangePreparator(context.getChooser(), this);
        } else {
            return new GOST01ClientKeyExchangePreparator(context.getChooser(), this);
        }
    }

    @Override
    public GOSTClientKeyExchangeSerializer getSerializer(Context context) {
        return new GOSTClientKeyExchangeSerializer(this);
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
