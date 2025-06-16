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
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.handler.PskEcDheServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.PskEcDheServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PskEcDheServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PskEcDheServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement(name = "PskEcDheServerKeyExchange")
public class PskEcDheServerKeyExchangeMessage extends ECDHEServerKeyExchangeMessage {

    private ModifiableByteArray identityHint;

    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger identityHintLength;

    public PskEcDheServerKeyExchangeMessage() {
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
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("PskEcDheServerKeyExchangeMessage:");
        sb.append("\n  Curve Type: ");
        if (this.curveType != null && this.curveType.getValue() != null) {
            sb.append(EllipticCurveType.getCurveType(this.curveType.getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Named Group: ");
        if (namedGroup != null && namedGroup.getValue() != null) {
            sb.append(NamedGroup.getNamedGroup(this.namedGroup.getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Public Key: ");
        if (getPublicKey() != null) {
            sb.append(ArrayConverter.bytesToHexString(getPublicKey().getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public PskEcDheServerKeyExchangeHandler getHandler(Context context) {
        return new PskEcDheServerKeyExchangeHandler(context.getTlsContext());
    }

    @Override
    public PskEcDheServerKeyExchangeParser getParser(Context context, InputStream stream) {
        return new PskEcDheServerKeyExchangeParser(stream, context.getTlsContext());
    }

    @Override
    public PskEcDheServerKeyExchangePreparator getPreparator(Context context) {
        return new PskEcDheServerKeyExchangePreparator(context.getChooser(), this);
    }

    @Override
    public PskEcDheServerKeyExchangeSerializer getSerializer(Context context) {
        return new PskEcDheServerKeyExchangeSerializer(
                this, context.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder();
        sb.append("ECDHE_PSK_SERVER_KEY_EXCHANGE");
        if (isRetransmission()) {
            sb.append(" (ret.)");
        }
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "PSK_ECDHE_SKE";
    }
}
