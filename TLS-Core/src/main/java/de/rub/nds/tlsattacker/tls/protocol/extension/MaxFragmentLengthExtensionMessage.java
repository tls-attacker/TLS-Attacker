/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.extension;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;

/**
 * Maximum Fragment Length Extension described in rfc3546
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class MaxFragmentLengthExtensionMessage extends ExtensionMessage {

    private MaxFragmentLength maxFragmentLengthConfig;

    /**
     * Maximum fragment length value described in rfc3546
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray maxFragmentLength;

    public MaxFragmentLengthExtensionMessage(TlsConfig tlsConfig) {
        super();
        this.extensionTypeConstant = ExtensionType.MAX_FRAGMENT_LENGTH;
        this.setMaxFragmentLength(tlsConfig.getMaxFragmentLength().getArrayValue());
    }

    public MaxFragmentLengthExtensionMessage() {
        super();
        this.extensionTypeConstant = ExtensionType.MAX_FRAGMENT_LENGTH;
    }

    public MaxFragmentLength getMaxFragmentLengthConfig() {
        return maxFragmentLengthConfig;
    }

    public void setMaxFragmentLengthConfig(MaxFragmentLength maxFragmentLengthConfig) {
        this.maxFragmentLengthConfig = maxFragmentLengthConfig;
    }

    public ModifiableByteArray getMaxFragmentLength() {
        return maxFragmentLength;
    }

    public void setMaxFragmentLength(ModifiableByteArray maxFragmentLength) {
        this.maxFragmentLength = maxFragmentLength;
    }

    public void setMaxFragmentLength(byte[] maxFragmentLength) {
        this.maxFragmentLength = ModifiableVariableFactory.safelySetValue(this.maxFragmentLength, maxFragmentLength);
    }

    @Override
    public ExtensionHandler<? extends ExtensionMessage> getExtensionHandler() {
        return new MaxFragmentLengthExtensionHandler();
    }

}
