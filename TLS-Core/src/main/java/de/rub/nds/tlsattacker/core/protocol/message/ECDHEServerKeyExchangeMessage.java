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
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.handler.ECDHEServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.message.computations.ECDHEServerComputations;
import de.rub.nds.tlsattacker.core.protocol.parser.ECDHEServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ECDHEServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ECDHEServerKeyExchangeSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.List;

@XmlRootElement(name = "ECDHEServerKeyExchange")
public class ECDHEServerKeyExchangeMessage<Self extends ECDHEServerKeyExchangeMessage<?>>
        extends ServerKeyExchangeMessage<Self> {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    protected ModifiableByte curveType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    protected ModifiableByteArray namedGroup;

    protected ECDHEServerComputations computations;

    public ECDHEServerKeyExchangeMessage() {
        super();
    }

    public ModifiableByte getGroupType() {
        return curveType;
    }

    public void setCurveType(ModifiableByte curveType) {
        this.curveType = curveType;
    }

    public void setCurveType(byte curveType) {
        this.curveType = ModifiableVariableFactory.safelySetValue(this.curveType, curveType);
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

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("ECDHEServerKeyExchangeMessage:");
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
        sb.append("\n  Public Key: ");
        if (getPublicKey() != null && getPublicKey().getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(getPublicKey().getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Signature and Hash Algorithm: ");
        // signature and hash algorithms are provided only while working with
        // (D)TLS 1.2
        if (this.getSignatureAndHashAlgorithm() != null
                && getSignatureAndHashAlgorithm().getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(getSignatureAndHashAlgorithm().getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Signature: ");
        if (getSignature() != null && getSignature().getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(getSignature().getValue()));
        } else {
            sb.append("null");
        }

        return sb.toString();
    }

    @Override
    public ECDHEServerComputations getComputations() {
        return computations;
    }

    @Override
    public ECDHEServerKeyExchangeHandler getHandler(TlsContext tlsContext) {
        return new ECDHEServerKeyExchangeHandler<>(tlsContext);
    }

    @Override
    public ECDHEServerKeyExchangeParser getParser(TlsContext tlsContext, InputStream stream) {
        return new ECDHEServerKeyExchangeParser(stream, tlsContext);
    }

    @Override
    public ECDHEServerKeyExchangePreparator getPreparator(TlsContext tlsContext) {
        return new ECDHEServerKeyExchangePreparator(tlsContext.getChooser(), this);
    }

    @Override
    public ECDHEServerKeyExchangeSerializer getSerializer(TlsContext tlsContext) {
        return new ECDHEServerKeyExchangeSerializer(
                this, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder();
        sb.append("ECDHE_SERVER_KEY_EXCHANGE");
        if (isRetransmission()) {
            sb.append(" (ret.)");
        }
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "ECDH_SKE";
    }

    @Override
    public void prepareComputations() {
        if (computations == null) {
            computations = new ECDHEServerComputations();
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
