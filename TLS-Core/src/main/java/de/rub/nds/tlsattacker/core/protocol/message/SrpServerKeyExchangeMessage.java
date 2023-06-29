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
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.handler.SrpServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.message.computations.SRPServerComputations;
import de.rub.nds.tlsattacker.core.protocol.parser.SrpServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.SrpServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.SrpServerKeyExchangeSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.List;

@XmlRootElement(name = "SrpServerKeyExchange")
public class SrpServerKeyExchangeMessage
        extends ServerKeyExchangeMessage<SrpServerKeyExchangeMessage> {

    /** SRP modulus */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableByteArray modulus;

    /** SRP modulus Length */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger modulusLength;

    /** SRP generator */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableByteArray generator;

    /** SRP generator Length */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger generatorLength;

    /** SRP salt */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableByteArray salt;

    /** SRP salt Length */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger saltLength;

    @HoldsModifiableVariable protected SRPServerComputations computations;

    public SrpServerKeyExchangeMessage() {
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
    public SRPServerComputations getComputations() {
        return computations;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("SrpServerKeyExchangeMessage:");
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
        if (this.getSignatureAndHashAlgorithm() != null
                && getSignatureAndHashAlgorithm().getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(getSignatureAndHashAlgorithm().getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Signature: ");
        if (this.getSignature() != null && getSignature().getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(this.getSignature().getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "SRP_SKE";
    }

    @Override
    public SrpServerKeyExchangeHandler getHandler(TlsContext tlsContext) {
        return new SrpServerKeyExchangeHandler(tlsContext);
    }

    @Override
    public SrpServerKeyExchangeParser getParser(TlsContext tlsContext, InputStream stream) {
        return new SrpServerKeyExchangeParser(stream, tlsContext);
    }

    @Override
    public SrpServerKeyExchangePreparator getPreparator(TlsContext tlsContext) {
        return new SrpServerKeyExchangePreparator(tlsContext.getChooser(), this);
    }

    @Override
    public SrpServerKeyExchangeSerializer getSerializer(TlsContext tlsContext) {
        return new SrpServerKeyExchangeSerializer(
                this, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder();
        sb.append("SRP_SERVER_KEY_EXCHANGE");
        if (isRetransmission()) {
            sb.append(" (ret.)");
        }
        return sb.toString();
    }

    @Override
    public void prepareComputations() {
        if (getComputations() == null) {
            computations = new SRPServerComputations();
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
