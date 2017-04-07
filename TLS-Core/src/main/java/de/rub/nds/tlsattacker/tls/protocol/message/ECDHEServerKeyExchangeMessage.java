/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.message;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.tls.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.ECDHEServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.protocol.message.computations.ECDHEServerComputations;
import de.rub.nds.tlsattacker.tls.protocol.message.computations.KeyExchangeComputations;
import de.rub.nds.tlsattacker.tls.protocol.serializer.ECDHEServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ECDHEServerKeyExchangeMessage extends ServerKeyExchangeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByte curveType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray namedCurve;

    private ECDHEServerComputations computations;

    public ECDHEServerKeyExchangeMessage() {
        super();
        computations = new ECDHEServerComputations();
    }

    public ECDHEServerKeyExchangeMessage(TlsConfig tlsConfig) {
        super(tlsConfig, HandshakeMessageType.SERVER_KEY_EXCHANGE);
        computations = new ECDHEServerComputations();
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
        sb.append(ArrayConverter.bytesToHexString(getSerializedPublicKey().getValue()));
        sb.append("\n  Signature Algorithm: ");
        // signature and hash algorithms are provided only while working with
        // (D)TLS 1.2
        if (this.getHashAlgorithm() != null) {
            sb.append(HashAlgorithm.getHashAlgorithm(this.getHashAlgorithm().getValue()));
            sb.append(" ");
        }
        if (this.getSignatureAlgorithm() != null) {
            sb.append(SignatureAlgorithm.getSignatureAlgorithm(this.getSignatureAlgorithm().getValue()));
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
    public KeyExchangeComputations getComputations() {
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
}
