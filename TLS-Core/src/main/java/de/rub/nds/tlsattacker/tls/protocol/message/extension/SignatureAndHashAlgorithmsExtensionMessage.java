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
import de.rub.nds.tlsattacker.tls.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.extension.SignatureAndHashAlgorithmsExtensionHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
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

    @Override
    public SignatureAndHashAlgorithmsExtensionHandler getHandler(TlsContext context) {
        return new SignatureAndHashAlgorithmsExtensionHandler(context);
    }
}
