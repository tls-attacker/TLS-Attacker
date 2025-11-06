/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.tokenbinding;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.protocol.crypto.signature.SignatureCalculator;
import de.rub.nds.protocol.crypto.signature.SignatureComputations;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.Context;
import java.io.InputStream;

public class TokenBindingMessage extends ProtocolMessage {

    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger tokenbindingsLength;

    @ModifiableVariableProperty private ModifiableByte tokenbindingType;

    @ModifiableVariableProperty private ModifiableByte keyParameter;

    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger keyLength;

    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger modulusLength;

    @ModifiableVariableProperty private ModifiableByteArray modulus;

    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger publicExponentLength;

    @ModifiableVariableProperty private ModifiableByteArray publicExponent;

    @ModifiableVariableProperty private ModifiableInteger pointLength;

    @ModifiableVariableProperty private ModifiableByteArray point;

    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger signatureLength;

    @ModifiableVariableProperty private ModifiableByteArray signature;

    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger extensionLength;

    @ModifiableVariableProperty private ModifiableByteArray extensionBytes;

    @HoldsModifiableVariable private SignatureComputations signatureComputations;

    public TokenBindingMessage() {
        super();
        protocolMessageType = ProtocolMessageType.APPLICATION_DATA;
    }

    @Override
    public String toCompactString() {
        return "TOKENBINDING";
    }

    public ModifiableInteger getTokenbindingsLength() {
        return tokenbindingsLength;
    }

    public void setTokenbindingsLength(ModifiableInteger tokenbindingsLength) {
        this.tokenbindingsLength = tokenbindingsLength;
    }

    public void setTokenbindingsLength(int tokenbindingsLength) {
        this.tokenbindingsLength =
                ModifiableVariableFactory.safelySetValue(
                        this.tokenbindingsLength, tokenbindingsLength);
    }

    public ModifiableInteger getModulusLength() {
        return modulusLength;
    }

    public void setModulusLength(int modulusLength) {
        this.modulusLength =
                ModifiableVariableFactory.safelySetValue(this.modulusLength, modulusLength);
    }

    public void setModulusLength(ModifiableInteger modulusLength) {
        this.modulusLength = modulusLength;
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

    public ModifiableInteger getPublicExponentLength() {
        return publicExponentLength;
    }

    public void setPublicExponentLength(ModifiableInteger publicExponentLength) {
        this.publicExponentLength = publicExponentLength;
    }

    public void setPublicExponentLength(int publicExponentLength) {
        this.publicExponentLength =
                ModifiableVariableFactory.safelySetValue(
                        this.publicExponentLength, publicExponentLength);
    }

    public ModifiableByteArray getPublicExponent() {
        return publicExponent;
    }

    public void setPublicExponent(ModifiableByteArray publicExponent) {
        this.publicExponent = publicExponent;
    }

    public void setPublicExponent(byte[] publicExponent) {
        this.publicExponent =
                ModifiableVariableFactory.safelySetValue(this.publicExponent, publicExponent);
    }

    public ModifiableInteger getKeyLength() {
        return keyLength;
    }

    public void setKeyLength(ModifiableInteger keyLength) {
        this.keyLength = keyLength;
    }

    public void setKeyLength(int keyLength) {
        this.keyLength = ModifiableVariableFactory.safelySetValue(this.keyLength, keyLength);
    }

    public ModifiableInteger getPointLength() {
        return pointLength;
    }

    public void setPointLength(ModifiableInteger pointLength) {
        this.pointLength = pointLength;
    }

    public void setPointLength(int pointLength) {
        this.pointLength = ModifiableVariableFactory.safelySetValue(this.pointLength, pointLength);
    }

    public ModifiableByteArray getPoint() {
        return point;
    }

    public void setPoint(ModifiableByteArray point) {
        this.point = point;
    }

    public void setPoint(byte[] point) {
        this.point = ModifiableVariableFactory.safelySetValue(this.point, point);
    }

    public ModifiableByte getTokenbindingType() {
        return tokenbindingType;
    }

    public void setTokenbindingType(ModifiableByte tokenbindingType) {
        this.tokenbindingType = tokenbindingType;
    }

    public void setTokenbindingType(byte tokenbindingType) {
        this.tokenbindingType =
                ModifiableVariableFactory.safelySetValue(this.tokenbindingType, tokenbindingType);
    }

    public ModifiableByte getKeyParameter() {
        return keyParameter;
    }

    public void setKeyParameter(ModifiableByte keyParameter) {
        this.keyParameter = keyParameter;
    }

    public void setKeyParameter(byte keyParameter) {
        this.keyParameter =
                ModifiableVariableFactory.safelySetValue(this.keyParameter, keyParameter);
    }

    public ModifiableInteger getSignatureLength() {
        return signatureLength;
    }

    public void setSignatureLength(ModifiableInteger signatureLength) {
        this.signatureLength = signatureLength;
    }

    public void setSignatureLength(int signatureLength) {
        this.signatureLength =
                ModifiableVariableFactory.safelySetValue(this.signatureLength, signatureLength);
    }

    public ModifiableByteArray getSignature() {
        return signature;
    }

    public void setSignature(ModifiableByteArray signature) {
        this.signature = signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = ModifiableVariableFactory.safelySetValue(this.signature, signature);
    }

    public ModifiableInteger getExtensionLength() {
        return extensionLength;
    }

    public void setExtensionLength(ModifiableInteger extensionLength) {
        this.extensionLength = extensionLength;
    }

    public void setExtensionLength(int extensionLength) {
        this.extensionLength =
                ModifiableVariableFactory.safelySetValue(this.extensionLength, extensionLength);
    }

    public ModifiableByteArray getExtensionBytes() {
        return extensionBytes;
    }

    public void setExtensionBytes(ModifiableByteArray extensionBytes) {
        this.extensionBytes = extensionBytes;
    }

    public void setExtensionBytes(byte[] extensionBytes) {
        this.extensionBytes =
                ModifiableVariableFactory.safelySetValue(this.extensionBytes, extensionBytes);
    }

    @Override
    public TokenBindingMessageHandler getHandler(Context context) {
        return new TokenBindingMessageHandler(context.getTlsContext());
    }

    @Override
    public TokenBindingMessageParser getParser(Context context, InputStream stream) {
        return new TokenBindingMessageParser(stream);
    }

    @Override
    public TokenBindingMessagePreparator getPreparator(Context context) {
        return new TokenBindingMessagePreparator(context.getChooser(), this);
    }

    @Override
    public TokenBindingMessageSerializer getSerializer(Context context) {
        return new TokenBindingMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "TB";
    }

    public SignatureComputations getSignatureComputations(SignatureAlgorithm algorithm) {
        // TODO its unlucky that this design can cause a conflict here if the type mismatches
        if (signatureComputations == null) {
            SignatureCalculator util = new SignatureCalculator();
            signatureComputations = util.createSignatureComputations(algorithm);
        }
        return signatureComputations;
    }
}
