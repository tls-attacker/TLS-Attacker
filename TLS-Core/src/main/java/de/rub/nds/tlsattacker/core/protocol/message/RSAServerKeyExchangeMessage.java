/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message;

import java.util.List;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.RSAServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.message.computations.RSAServerComputations;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "RSAServerKeyExchange")
public class RSAServerKeyExchangeMessage extends ServerKeyExchangeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    protected ModifiableByteArray modulus;
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    protected ModifiableInteger modulusLength;

    @HoldsModifiableVariable
    protected RSAServerComputations computations;

    public RSAServerKeyExchangeMessage() {
        super();
    }

    public RSAServerKeyExchangeMessage(Config tlsConfig) {
        super(tlsConfig, HandshakeMessageType.SERVER_KEY_EXCHANGE);
    }

    @Override
    public RSAServerComputations getComputations() {
        return computations;
    }

    @Override
    public void prepareComputations() {
        if (getComputations() == null) {
            computations = new RSAServerComputations();
        }
    }

    @Override
    public ProtocolMessageHandler<RSAServerKeyExchangeMessage> getHandler(TlsContext context) {
        return new RSAServerKeyExchangeHandler(context);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("RSAServerKeyExchangeMessage:");
        sb.append("\n  Modulus N: ");
        if (modulus != null && modulus.getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(modulus.getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Public Key e: ");
        if (getPublicKey() != null && getPublicKey().getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(getPublicKey().getValue(), false));
        } else {
            sb.append("null");
        }
        sb.append("\n  Signature and Hash Algorithm: ");
        // signature and hash algorithms are provided only while working with
        // (D)TLS 1.2
        if (this.getSignatureAndHashAlgorithm() != null && this.getSignatureAndHashAlgorithm().getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(getSignatureAndHashAlgorithm().getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Signature: ");
        if (this.getSignature() != null && this.getSignature().getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(this.getSignature().getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public String toCompactString() {
        return "RSA_SERVER_KEY_EXCHANGE";
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (computations != null) {
            holders.add(computations);
        }
        return holders;
    }

    public ModifiableByteArray getModulus() {
        return modulus;
    }

    public void setModulus(byte[] modulus) {
        this.modulus = ModifiableVariableFactory.safelySetValue(this.modulus, modulus);
    }

    public void setModulus(ModifiableByteArray modulus) {
        this.modulus = modulus;
    }

    public void setModulusLength(ModifiableInteger modulusLength) {
        this.modulusLength = modulusLength;
    }

    public ModifiableInteger getModulusLength() {
        return modulusLength;
    }

    public void setModulusLength(int modulusLength) {
        this.modulusLength = ModifiableVariableFactory.safelySetValue(this.modulusLength, modulusLength);
    }
}
