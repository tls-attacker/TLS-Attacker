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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.TokenBindingExtensionHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class TokenBindingExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty
    private ModifiableByteArray tokenbindingVersion;
    @ModifiableVariableProperty
    private ModifiableByteArray tokenbindingKeyParameters;
    private int parameterListLength;

    public TokenBindingExtensionMessage() {
        super(ExtensionType.TOKEN_BINDING);
    }

    public ModifiableByteArray getTokenbindingVersion() {
        return tokenbindingVersion;
    }

    public void setTokenbindingVersion(ModifiableByteArray tokenbindingVersion) {
        this.tokenbindingVersion = tokenbindingVersion;
    }

    public void setTokenbindingVersion(byte[] tokenbindingVersion) {
        this.tokenbindingVersion = ModifiableVariableFactory.safelySetValue(this.tokenbindingVersion,
                tokenbindingVersion);
    }

    public ModifiableByteArray getTokenbindingKeyParameters() {
        return tokenbindingKeyParameters;
    }

    public void setTokenbindingKeyParameters(ModifiableByteArray tokenbindingKeyParameters) {
        this.tokenbindingKeyParameters = tokenbindingKeyParameters;
    }

    public void setTokenbindingKeyParameters(byte[] tokenbindingParameters) {
        this.tokenbindingKeyParameters = ModifiableVariableFactory.safelySetValue(this.tokenbindingKeyParameters,
                tokenbindingParameters);
    }

    public int getParameterListLength() {
        return parameterListLength;
    }

    public void setParameterListLength(int parameterListLength) {
        this.parameterListLength = parameterListLength;
    }

}
