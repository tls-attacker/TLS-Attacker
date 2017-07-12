/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.handler.DHEServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.computations.DHEServerComputations;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.util.List;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
@XmlRootElement
public class DHEServerKeyExchangeMessage extends ServerKeyExchangeMessage {

    /**
     * DH modulus
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableByteArray p;

    /**
     * DH modulus Length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger pLength;

    /**
     * DH generator
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableByteArray g;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger gLength;

    @HoldsModifiableVariable
    protected DHEServerComputations computations;

    public DHEServerKeyExchangeMessage() {
        super();
    }

    public DHEServerKeyExchangeMessage(TlsConfig tlsConfig) {
        super(tlsConfig, HandshakeMessageType.SERVER_KEY_EXCHANGE);
    }

    public ModifiableByteArray getP() {
        return p;
    }

    public void setP(ModifiableByteArray p) {
        this.p = p;
    }

    public void setP(byte[] p) {
        this.p = ModifiableVariableFactory.safelySetValue(this.p, p);
    }

    public ModifiableByteArray getG() {
        return g;
    }

    public void setG(ModifiableByteArray g) {
        this.g = g;
    }

    public void setG(byte[] g) {
        this.g = ModifiableVariableFactory.safelySetValue(this.g, g);
    }

    public ModifiableInteger getpLength() {
        return pLength;
    }

    public void setpLength(ModifiableInteger pLength) {
        this.pLength = pLength;
    }

    public void setpLength(int pLength) {
        this.pLength = ModifiableVariableFactory.safelySetValue(this.pLength, pLength);
    }

    public ModifiableInteger getgLength() {
        return gLength;
    }

    public void setgLength(ModifiableInteger gLength) {
        this.gLength = gLength;
    }

    public void setgLength(int gLength) {
        this.gLength = ModifiableVariableFactory.safelySetValue(this.gLength, gLength);
    }

    @Override
    public DHEServerComputations getComputations() {
        return computations;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(super.toString());
        sb.append("\n  Modulus p: ");
        if (p != null) {
            sb.append(ArrayConverter.bytesToHexString(p.getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Generator g: ");
        if (g != null) {
            sb.append(ArrayConverter.bytesToHexString(g.getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Public Key: ");
        if (getSerializedPublicKey() != null) {
            sb.append(ArrayConverter.bytesToHexString(getSerializedPublicKey().getValue(), false));
        } else {
            sb.append("null");
        }
        sb.append("\n  Signature and Hash Algorithm: ");
        // signature and hash algorithms are provided only while working with
        // (D)TLS 1.2
        if (this.getSignatureAndHashAlgorithm() != null) {
            sb.append(ArrayConverter.bytesToHexString(getSignatureAndHashAlgorithm().getValue()));
        }
        sb.append("\n  Signature: ");
        if (this.getSignature() != null) {
            sb.append(ArrayConverter.bytesToHexString(this.getSignature().getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new DHEServerKeyExchangeHandler(context);
    }

    @Override
    public String toCompactString() {
        return "DHE_SERVER_KEY_EXCHANGE";
    }

    @Override
    public void prepareComputations() {
        if (getComputations() == null) {
            computations = new DHEServerComputations();
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
