/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * This extension is defined in draft-ietf-tokbind-negotiation
 */
@XmlRootElement(name = "TokenBindingExtension")
public class TokenBindingExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty
    private ModifiableByteArray tokenbindingVersion;
    @ModifiableVariableProperty
    private ModifiableByteArray tokenbindingKeyParameters;
    private ModifiableInteger parameterListLength;

    public TokenBindingExtensionMessage() {
        super(ExtensionType.TOKEN_BINDING);
    }

    public TokenBindingExtensionMessage(Config config) {
        super(ExtensionType.TOKEN_BINDING);
    }

    public ModifiableByteArray getTokenbindingVersion() {
        return tokenbindingVersion;
    }

    public void setTokenbindingVersion(ModifiableByteArray tokenbindingVersion) {
        this.tokenbindingVersion = tokenbindingVersion;
    }

    public void setTokenbindingVersion(byte[] tokenbindingVersion) {
        this.tokenbindingVersion =
            ModifiableVariableFactory.safelySetValue(this.tokenbindingVersion, tokenbindingVersion);
    }

    public ModifiableByteArray getTokenbindingKeyParameters() {
        return tokenbindingKeyParameters;
    }

    public void setTokenbindingKeyParameters(ModifiableByteArray tokenbindingKeyParameters) {
        this.tokenbindingKeyParameters = tokenbindingKeyParameters;
    }

    public void setTokenbindingKeyParameters(byte[] tokenbindingParameters) {
        this.tokenbindingKeyParameters =
            ModifiableVariableFactory.safelySetValue(this.tokenbindingKeyParameters, tokenbindingParameters);
    }

    public ModifiableInteger getParameterListLength() {
        return parameterListLength;
    }

    public void setParameterListLength(ModifiableInteger parameterListLength) {
        this.parameterListLength = parameterListLength;
    }

    public void setParameterListLength(int parameterListLength) {
        this.parameterListLength =
            ModifiableVariableFactory.safelySetValue(this.parameterListLength, parameterListLength);
    }

}
