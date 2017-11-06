/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;

/**
 * This extension is defined in RFC5246
 */
public class SignatureAndHashAlgorithmsExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger signatureAndHashAlgorithmsLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray signatureAndHashAlgorithms;

    public SignatureAndHashAlgorithmsExtensionMessage() {
        super(ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS);
    }

    public ModifiableInteger getSignatureAndHashAlgorithmsLength() {
        return signatureAndHashAlgorithmsLength;
    }

    public void setSignatureAndHashAlgorithmsLength(int length) {
        this.signatureAndHashAlgorithmsLength = ModifiableVariableFactory.safelySetValue(
                this.signatureAndHashAlgorithmsLength, length);
    }

    public ModifiableByteArray getSignatureAndHashAlgorithms() {
        return signatureAndHashAlgorithms;
    }

    public void setSignatureAndHashAlgorithms(byte[] array) {
        this.signatureAndHashAlgorithms = ModifiableVariableFactory.safelySetValue(this.signatureAndHashAlgorithms,
                array);
    }

    public void setSignatureAndHashAlgorithmsLength(ModifiableInteger signatureAndHashAlgorithmsLength) {
        this.signatureAndHashAlgorithmsLength = signatureAndHashAlgorithmsLength;
    }

    public void setSignatureAndHashAlgorithms(ModifiableByteArray signatureAndHashAlgorithms) {
        this.signatureAndHashAlgorithms = signatureAndHashAlgorithms;
    }
}
