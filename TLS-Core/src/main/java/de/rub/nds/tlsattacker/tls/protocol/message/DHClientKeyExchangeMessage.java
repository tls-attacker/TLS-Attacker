/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.message;

import de.rub.nds.tlsattacker.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.tls.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.DHClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.protocol.message.computations.DHClientComputations;
import de.rub.nds.tlsattacker.tls.protocol.message.computations.KeyExchangeComputations;
import de.rub.nds.tlsattacker.tls.protocol.serializer.DHClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.math.BigInteger;
import java.util.List;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
@XmlRootElement
public class DHClientKeyExchangeMessage extends ClientKeyExchangeMessage {

    /**
     * DH modulus
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableBigInteger p;
    /**
     * DH generator
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableBigInteger g;
    /**
     * server's public key
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableBigInteger y;

    @HoldsModifiableVariable
    protected DHClientComputations computations;

    public DHClientKeyExchangeMessage() {
        super();
    }

    public DHClientKeyExchangeMessage(TlsConfig tlsConfig) {
        super(tlsConfig);
    }

    public ModifiableBigInteger getP() {
        return p;
    }

    public void setP(ModifiableBigInteger p) {
        this.p = p;
    }

    public void setP(BigInteger p) {
        this.p = ModifiableVariableFactory.safelySetValue(this.p, p);
    }

    public ModifiableBigInteger getG() {
        return g;
    }

    public void setG(ModifiableBigInteger g) {
        this.g = g;
    }

    public void setG(BigInteger g) {
        this.g = ModifiableVariableFactory.safelySetValue(this.g, g);
    }

    public ModifiableBigInteger getY() {
        return y;
    }

    public void setY(ModifiableBigInteger y) {
        this.y = y;
    }

    public void setY(BigInteger y) {
        this.y = ModifiableVariableFactory.safelySetValue(this.y, y);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(super.toString());
        sb.append("\n  Y (client's public key): ");
        if (y != null) {
            sb.append(y.getValue().toString(16));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public DHClientComputations getComputations() {
        return computations;
    }

    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new DHClientKeyExchangeHandler(context);
    }

    @Override
    public String toCompactString() {
        return "DH_CLIENT_KEY_EXCHANGE";
    }

    @Override
    public void prepareComputations() {
        if (getComputations() == null) {
            computations = new DHClientComputations();
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
