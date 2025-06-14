/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableHolder;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.protocol.handler.SrpClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.message.computations.SRPClientComputations;
import de.rub.nds.tlsattacker.core.protocol.parser.SrpClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.SrpClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.SrpClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.List;

@XmlRootElement(name = "SrpClientKeyExchange")
public class SrpClientKeyExchangeMessage extends ClientKeyExchangeMessage {

    /** SRP modulus */
    @ModifiableVariableProperty private ModifiableByteArray modulus;

    /** SRP modulus Length */
    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger modulusLength;

    /** SRP generator */
    @ModifiableVariableProperty private ModifiableByteArray generator;

    /** SRP generator Length */
    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger generatorLength;

    @HoldsModifiableVariable protected SRPClientComputations computations;

    /** SRP salt */
    @ModifiableVariableProperty private ModifiableByteArray salt;

    /** SRP salt Length */
    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger saltLength;

    public SrpClientKeyExchangeMessage() {
        super();
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
        this.modulusLength =
                ModifiableVariableFactory.safelySetValue(this.modulusLength, modulusLength);
    }

    public ModifiableInteger getGeneratorLength() {
        return generatorLength;
    }

    public void setGeneratorLength(ModifiableInteger generatorLength) {
        this.generatorLength = generatorLength;
    }

    public void setGeneratorLength(int generatorLength) {
        this.generatorLength =
                ModifiableVariableFactory.safelySetValue(this.generatorLength, generatorLength);
    }

    @Override
    public SRPClientComputations getComputations() {
        return computations;
    }

    @Override
    public SrpClientKeyExchangeHandler getHandler(Context context) {
        return new SrpClientKeyExchangeHandler(context.getTlsContext());
    }

    @Override
    public SrpClientKeyExchangeParser getParser(Context context, InputStream stream) {
        return new SrpClientKeyExchangeParser(stream, context.getTlsContext());
    }

    @Override
    public SrpClientKeyExchangePreparator getPreparator(Context context) {
        return new SrpClientKeyExchangePreparator(context.getChooser(), this);
    }

    @Override
    public SrpClientKeyExchangeSerializer getSerializer(Context context) {
        return new SrpClientKeyExchangeSerializer(this);
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder();
        sb.append("SRP_CLIENT_KEY_EXCHANGE");
        if (isRetransmission()) {
            sb.append(" (ret.)");
        }
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "SRP_CKE";
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
