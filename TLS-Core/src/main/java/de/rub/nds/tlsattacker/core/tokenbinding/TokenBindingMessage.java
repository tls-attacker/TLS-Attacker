/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.tokenbinding;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class TokenBindingMessage extends ProtocolMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger tokenbindingsLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByte tokenbindingType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByte keyParameter;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger keyLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger modulusLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableByteArray modulus;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger publicExponentLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableByteArray publicExponent;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableInteger pointLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableByteArray point;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger signatureLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.SIGNATURE)
    private ModifiableByteArray signature;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger extensionLength;

    @ModifiableVariableProperty
    private ModifiableByteArray extensionBytes;

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
        this.tokenbindingsLength = ModifiableVariableFactory.safelySetValue(this.tokenbindingsLength,
                tokenbindingsLength);
    }

    public ModifiableInteger getModulusLength() {
        return modulusLength;
    }

    public void setModulusLength(int modulusLength) {
        this.modulusLength = ModifiableVariableFactory.safelySetValue(this.modulusLength, modulusLength);
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
        this.publicExponentLength = ModifiableVariableFactory.safelySetValue(this.publicExponentLength,
                publicExponentLength);
    }

    public ModifiableByteArray getPublicExponent() {
        return publicExponent;
    }

    public void setPublicExponent(ModifiableByteArray publicExponent) {
        this.publicExponent = publicExponent;
    }

    public void setPublicExponent(byte[] publicExponent) {
        this.publicExponent = ModifiableVariableFactory.safelySetValue(this.publicExponent, publicExponent);
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
        this.tokenbindingType = ModifiableVariableFactory.safelySetValue(this.tokenbindingType, tokenbindingType);
    }

    public ModifiableByte getKeyParameter() {
        return keyParameter;
    }

    public void setKeyParameter(ModifiableByte keyParameter) {
        this.keyParameter = keyParameter;
    }

    public void setKeyParameter(byte keyParameter) {
        this.keyParameter = ModifiableVariableFactory.safelySetValue(this.keyParameter, keyParameter);
    }

    public ModifiableInteger getSignatureLength() {
        return signatureLength;
    }

    public void setSignatureLength(ModifiableInteger signatureLength) {
        this.signatureLength = signatureLength;
    }

    public void setSignatureLength(int signatureLength) {
        this.signatureLength = ModifiableVariableFactory.safelySetValue(this.signatureLength, signatureLength);
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
        this.extensionLength = ModifiableVariableFactory.safelySetValue(this.extensionLength, extensionLength);
    }

    public ModifiableByteArray getExtensionBytes() {
        return extensionBytes;
    }

    public void setExtensionBytes(ModifiableByteArray extensionBytes) {
        this.extensionBytes = extensionBytes;
    }

    public void setExtensionBytes(byte[] extensionbytes) {
        this.extensionBytes = ModifiableVariableFactory.safelySetValue(this.extensionBytes, extensionbytes);
    }

    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new TokenBindingMessageHandler(context);
    }
}
