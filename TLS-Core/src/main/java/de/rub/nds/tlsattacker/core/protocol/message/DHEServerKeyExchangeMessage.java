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
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.handler.DHEServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.message.computations.DHEServerComputations;
import de.rub.nds.tlsattacker.core.protocol.parser.DHEServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.DHEServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.DHEServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.List;

@XmlRootElement(name = "DHEServerKeyExchange")
public class DHEServerKeyExchangeMessage extends ServerKeyExchangeMessage {

    /** DH modulus */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    protected ModifiableByteArray modulus;

    /** DH modulus Length */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    protected ModifiableInteger modulusLength;

    /** DH generator */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    protected ModifiableByteArray generator;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    protected ModifiableInteger generatorLength;

    @HoldsModifiableVariable protected DHEServerComputations computations;

    public DHEServerKeyExchangeMessage() {
        super();
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
    public DHEServerComputations getKeyExchangeComputations() {
        return computations;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("DHEServerKeyExchangeMessage:");
        sb.append("\n  Modulus p: ");
        if (modulus != null && modulus.getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(modulus.getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Generator g: ");
        if (generator != null && generator.getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(generator.getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Public Key: ");
        if (getPublicKey() != null && getPublicKey().getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(getPublicKey().getValue(), false));
        } else {
            sb.append("null");
        }
        sb.append("\n  Signature and Hash Algorithm: ");
        // signature and hash algorithms are provided only while working with
        // (D)TLS 1.2
        if (this.getSignatureAndHashAlgorithm() != null
                && this.getSignatureAndHashAlgorithm().getValue() != null) {
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
    public DHEServerKeyExchangeHandler<? extends DHEServerKeyExchangeMessage> getHandler(
            Context context) {
        return new DHEServerKeyExchangeHandler<>(context.getTlsContext());
    }

    @Override
    public DHEServerKeyExchangeParser<? extends DHEServerKeyExchangeMessage> getParser(
            Context context, InputStream stream) {
        return new DHEServerKeyExchangeParser<>(stream, context.getTlsContext());
    }

    @Override
    public DHEServerKeyExchangePreparator<? extends DHEServerKeyExchangeMessage> getPreparator(
            Context context) {
        return new DHEServerKeyExchangePreparator<>(context.getChooser(), this);
    }

    @Override
    public DHEServerKeyExchangeSerializer<? extends DHEServerKeyExchangeMessage> getSerializer(
            Context context) {
        return new DHEServerKeyExchangeSerializer<>(
                this, context.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder();
        sb.append("DHE_SERVER_KEY_EXCHANGE");
        if (isRetransmission()) {
            sb.append(" (ret.)");
        }
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "DH_SKE";
    }

    @Override
    public void prepareKeyExchangeComputations() {
        if (getKeyExchangeComputations() == null) {
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
