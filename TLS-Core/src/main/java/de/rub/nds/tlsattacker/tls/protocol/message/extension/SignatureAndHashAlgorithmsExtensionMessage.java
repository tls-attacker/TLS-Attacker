/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.message.extension;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class SignatureAndHashAlgorithmsExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger signatureAndHashAlgorithmsLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray signatureAndHashAlgorithms;

    public SignatureAndHashAlgorithmsExtensionMessage(TlsConfig tlsConfig) {
        super();
        this.extensionTypeConstant = ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS;

    }

    public SignatureAndHashAlgorithmsExtensionMessage() {
        super();
        this.extensionTypeConstant = ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS;
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

    @Override
    public ExtensionPreparator<? extends ExtensionMessage> getExtensionPreparator() {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    @Override
    public ExtensionSerializer<? extends ExtensionMessage> getExtensionSerializer() {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }
}
