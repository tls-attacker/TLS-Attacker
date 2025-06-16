/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.handler.PskDhClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.PskDhClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PskDhClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PskDhClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement(name = "PskDhClientKeyExchange")
public class PskDhClientKeyExchangeMessage extends DHClientKeyExchangeMessage {

    @ModifiableVariableProperty private ModifiableByteArray identity;

    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger identityLength;

    public PskDhClientKeyExchangeMessage() {
        super();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("PskDhClientKeyExchangeMessage:");
        sb.append("\n  PSKIdentity Length: ");
        if (identityLength != null && identityLength.getValue() != null) {
            sb.append(identityLength.getValue());
        } else {
            sb.append("null");
        }
        sb.append("\n  PSKIdentity: ");
        if (identity != null && identity.getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(identity.getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
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

    public ModifiableInteger getIdentityLength() {
        return identityLength;
    }

    public void setIdentityLength(ModifiableInteger identityLength) {
        this.identityLength = identityLength;
    }

    public void setIdentityLength(int identityLength) {
        this.identityLength =
                ModifiableVariableFactory.safelySetValue(this.identityLength, identityLength);
    }

    @Override
    public PskDhClientKeyExchangeHandler getHandler(Context context) {
        return new PskDhClientKeyExchangeHandler(context.getTlsContext());
    }

    @Override
    public PskDhClientKeyExchangeParser getParser(Context context, InputStream stream) {
        return new PskDhClientKeyExchangeParser(stream, context.getTlsContext());
    }

    @Override
    public PskDhClientKeyExchangePreparator getPreparator(Context context) {
        return new PskDhClientKeyExchangePreparator(context.getChooser(), this);
    }

    @Override
    public PskDhClientKeyExchangeSerializer getSerializer(Context context) {
        return new PskDhClientKeyExchangeSerializer(this);
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder();
        sb.append("PSK_DH_CLIENT_KEY_EXCHANGE");
        if (isRetransmission()) {
            sb.append(" (ret.)");
        }
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "PSK_DH_CKE";
    }
}
