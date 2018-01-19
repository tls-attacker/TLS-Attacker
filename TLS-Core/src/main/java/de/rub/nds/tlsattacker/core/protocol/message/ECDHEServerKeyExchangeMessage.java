/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.handler.ECDHEServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.computations.ECDHEServerComputations;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.List;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class ECDHEServerKeyExchangeMessage extends ServerKeyExchangeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    protected ModifiableByte curveType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    protected ModifiableByteArray namedCurve;

    protected ECDHEServerComputations computations;

    public ECDHEServerKeyExchangeMessage() {
        super();
    }

    public ECDHEServerKeyExchangeMessage(Config tlsConfig) {
        super(tlsConfig, HandshakeMessageType.SERVER_KEY_EXCHANGE);
    }

    public ModifiableByte getCurveType() {
        return curveType;
    }

    public void setCurveType(ModifiableByte curveType) {
        this.curveType = curveType;
    }

    public void setCurveType(byte curveType) {
        this.curveType = ModifiableVariableFactory.safelySetValue(this.curveType, curveType);
    }

    public ModifiableByteArray getNamedCurve() {
        return namedCurve;
    }

    public void setNamedCurve(ModifiableByteArray namedCurve) {
        this.namedCurve = namedCurve;
    }

    public void setNamedCurve(byte[] namedCurve) {
        this.namedCurve = ModifiableVariableFactory.safelySetValue(this.namedCurve, namedCurve);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(super.toString());
        sb.append("\n  Curve Type: ");
        sb.append(EllipticCurveType.getCurveType(this.curveType.getValue()));
        sb.append("\n  Named Curve: ");
        if (namedCurve != null) {
            sb.append(NamedCurve.getNamedCurve(this.namedCurve.getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Public Key: ");
        sb.append(ArrayConverter.bytesToHexString(getPublicKey().getValue()));
        sb.append("\n  Signature and Hash Algorithm: ");
        // signature and hash algorithms are provided only while working with
        // (D)TLS 1.2
        if (this.getSignatureAndHashAlgorithm() != null) {
            sb.append(ArrayConverter.bytesToHexString(getSignatureAndHashAlgorithm().getValue()));
        }
        sb.append("\n  Signature: ");
        if (getSignature() != null) {
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
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new ECDHEServerKeyExchangeHandler(context);
    }

    @Override
    public String toCompactString() {
        return "ECDHE_SERVER_KEY_EXCHANGE";
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
