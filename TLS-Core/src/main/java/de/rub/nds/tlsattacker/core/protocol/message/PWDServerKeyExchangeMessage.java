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
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.handler.PWDServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.message.computations.PWDComputations;
import de.rub.nds.tlsattacker.core.protocol.parser.PWDServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PWDServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PWDServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement(name = "PWDServerKeyExchange")
public class PWDServerKeyExchangeMessage extends ServerKeyExchangeMessage {

    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger saltLength;

    @ModifiableVariableProperty private ModifiableByteArray salt;

    @ModifiableVariableProperty protected ModifiableByte curveType;

    @ModifiableVariableProperty protected ModifiableByteArray namedGroup;

    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger elementLength;

    @ModifiableVariableProperty private ModifiableByteArray element;

    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger scalarLength;

    @ModifiableVariableProperty private ModifiableByteArray scalar;

    protected PWDComputations computations;

    public PWDServerKeyExchangeMessage() {
        super();
    }

    @Override
    public PWDComputations getKeyExchangeComputations() {
        return computations;
    }

    @Override
    public void prepareKeyExchangeComputations() {
        if (getKeyExchangeComputations() == null) {
            computations = new PWDComputations();
        }
    }

    @Override
    public PWDServerKeyExchangeHandler getHandler(Context context) {
        return new PWDServerKeyExchangeHandler(context.getTlsContext());
    }

    @Override
    public PWDServerKeyExchangeParser getParser(Context context, InputStream stream) {
        return new PWDServerKeyExchangeParser(stream, context.getTlsContext());
    }

    @Override
    public PWDServerKeyExchangePreparator getPreparator(Context context) {
        return new PWDServerKeyExchangePreparator(context.getChooser(), this);
    }

    @Override
    public PWDServerKeyExchangeSerializer getSerializer(Context context) {
        return new PWDServerKeyExchangeSerializer(
                this, context.getChooser().getSelectedProtocolVersion());
    }

    public ModifiableInteger getSaltLength() {
        return saltLength;
    }

    public void setSaltLength(ModifiableInteger saltLength) {
        this.saltLength = saltLength;
    }

    public void setSaltLength(int saltLength) {
        this.saltLength = ModifiableVariableFactory.safelySetValue(this.saltLength, saltLength);
    }

    public ModifiableByteArray getSalt() {
        return salt;
    }

    public void setSalt(ModifiableByteArray salt) {
        this.salt = salt;
    }

    public void setSalt(byte[] salt) {
        this.salt = ModifiableVariableFactory.safelySetValue(this.salt, salt);
    }

    public void setCurveType(ModifiableByte curveType) {
        this.curveType = curveType;
    }

    public void setCurveType(byte curveType) {
        this.curveType = ModifiableVariableFactory.safelySetValue(this.curveType, curveType);
    }

    public ModifiableByte getGroupType() {
        return curveType;
    }

    public ModifiableByteArray getNamedGroup() {
        return namedGroup;
    }

    public void setNamedGroup(ModifiableByteArray namedGroup) {
        this.namedGroup = namedGroup;
    }

    public void setNamedGroup(byte[] namedGroup) {
        this.namedGroup = ModifiableVariableFactory.safelySetValue(this.namedGroup, namedGroup);
    }

    public ModifiableInteger getElementLength() {
        return elementLength;
    }

    public void setElementLength(ModifiableInteger elementLength) {
        this.elementLength = elementLength;
    }

    public void setElementLength(int elementLength) {
        this.elementLength =
                ModifiableVariableFactory.safelySetValue(this.elementLength, elementLength);
    }

    public ModifiableByteArray getElement() {
        return element;
    }

    public void setElement(ModifiableByteArray element) {
        this.element = element;
    }

    public void setElement(byte[] element) {
        this.element = ModifiableVariableFactory.safelySetValue(this.element, element);
    }

    public ModifiableInteger getScalarLength() {
        return scalarLength;
    }

    public void setScalarLength(ModifiableInteger scalarLength) {
        this.scalarLength = scalarLength;
    }

    public void setScalarLength(int scalarLength) {
        this.scalarLength =
                ModifiableVariableFactory.safelySetValue(this.scalarLength, scalarLength);
    }

    public ModifiableByteArray getScalar() {
        return scalar;
    }

    public void setScalar(ModifiableByteArray scalar) {
        this.scalar = scalar;
    }

    public void setScalar(byte[] scalar) {
        this.scalar = ModifiableVariableFactory.safelySetValue(this.scalar, scalar);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("PWDServerKeyExchangeMessage:");
        sb.append("\n  Salt: ");
        if (getSalt() != null && getSalt().getValue() != null) {
            sb.append(DataConverter.bytesToHexString(getSalt().getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Curve Type: ");
        if (curveType != null && curveType.getValue() != null) {
            sb.append(EllipticCurveType.getCurveType(this.curveType.getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Named Curve: ");
        if (namedGroup != null && namedGroup.getValue() != null) {
            sb.append(NamedGroup.getNamedGroup(this.namedGroup.getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Element: ");
        if (getElement() != null && getElement().getValue() != null) {
            sb.append(DataConverter.bytesToHexString(getElement().getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Scalar: ");
        if (getScalar() != null && getScalar().getValue() != null) {
            sb.append(DataConverter.bytesToHexString(getScalar().getValue()));
        } else {
            sb.append("null");
        }

        return sb.toString();
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder();
        sb.append("PWD_SERVER_KEY_EXCHANGE");
        if (isRetransmission()) {
            sb.append(" (ret.)");
        }
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "PWD_SKE";
    }
}
