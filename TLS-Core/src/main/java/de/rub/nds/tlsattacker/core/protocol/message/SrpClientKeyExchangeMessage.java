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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.SrpClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.message.computations.SRPClientComputations;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.List;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class SrpClientKeyExchangeMessage extends ClientKeyExchangeMessage {
    /**
     * SRP modulus
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableByteArray modulus;

    /**
     * SRP modulus Length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger modulusLength;

    /**
     * SRP generator
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableByteArray generator;

    /**
     * SRP generator Length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger generatorLength;

    @HoldsModifiableVariable
    protected SRPClientComputations computations;

    /**
     * SRP salt
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableByteArray salt;

    /**
     * SRP salt Length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger saltLength;

    public SrpClientKeyExchangeMessage() {
        super();
    }

    public SrpClientKeyExchangeMessage(Config tlsConfig) {
        super(tlsConfig);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("SrpClientKeyExchangeMessage:\n");
        return sb.toString();
    }

    public ModifiableByteArray getModulus() {
        return modulus;
    }

    public void setModulus(ModifiableByteArray modulus) {
        this.modulus = modulus;
    }

    public void setModulus(byte[] modulus) {
        this.modulus = ModifiableVariableFactory.safelySetValue(this.modulus, modulus);
    }

    public ModifiableByteArray getGenerator() {
        return generator;
    }

    public void setGenerator(ModifiableByteArray generator) {
        this.generator = generator;
    }

    public void setGenerator(byte[] generator) {
        this.generator = ModifiableVariableFactory.safelySetValue(this.generator, generator);
    }

    public ModifiableInteger getModulusLength() {
        return modulusLength;
    }

    public void setModulusLength(ModifiableInteger modulusLength) {
        this.modulusLength = modulusLength;
    }

    public void setModulusLength(int modulusLength) {
        this.modulusLength = ModifiableVariableFactory.safelySetValue(this.modulusLength, modulusLength);
    }

    public ModifiableInteger getGeneratorLength() {
        return generatorLength;
    }

    public void setGeneratorLength(ModifiableInteger generatorLength) {
        this.generatorLength = generatorLength;
    }

    public void setGeneratorLength(int generatorLength) {
        this.generatorLength = ModifiableVariableFactory.safelySetValue(this.generatorLength, generatorLength);
    }

    @Override
    public SRPClientComputations getComputations() {
        return computations;
    }

    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new SrpClientKeyExchangeHandler(context);
    }

    @Override
    public String toCompactString() {
        return "SRP_CLIENT_KEY_EXCHANGE";
    }

    @Override
    public void prepareComputations() {
        if (getComputations() == null) {
            computations = new SRPClientComputations();
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

    public ModifiableByteArray getSalt() {
        return salt;
    }

    public void setSalt(ModifiableByteArray salt) {
        this.salt = salt;
    }

    public void setSalt(byte[] salt) {
        this.salt = ModifiableVariableFactory.safelySetValue(this.salt, salt);
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
}
