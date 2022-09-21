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
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * This extension is defined in draft-ietf-tokbind-negotiation
 */
@XmlRootElement(name = "TokenBindingExtension")
public class TokenBindingExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty
    private ModifiableByteArray tokenBindingVersion;
    @ModifiableVariableProperty
    private ModifiableByteArray tokenBindingKeyParameters;
    private ModifiableInteger parameterListLength;

    public TokenBindingExtensionMessage() {
        super(ExtensionType.TOKEN_BINDING);
    }

    public TokenBindingExtensionMessage(Config config) {
        super(ExtensionType.TOKEN_BINDING);
    }

    public ModifiableByteArray getTokenBindingVersion() {
        return tokenBindingVersion;
    }

    public void setTokenBindingVersion(ModifiableByteArray tokenBindingVersion) {
        this.tokenBindingVersion = tokenBindingVersion;
    }

    public void setTokenBindingVersion(byte[] tokenBindingVersion) {
        this.tokenBindingVersion =
            ModifiableVariableFactory.safelySetValue(this.tokenBindingVersion, tokenBindingVersion);
    }

    public ModifiableByteArray getTokenBindingKeyParameters() {
        return tokenBindingKeyParameters;
    }

    public void setTokenBindingKeyParameters(ModifiableByteArray tokenBindingKeyParameters) {
        this.tokenBindingKeyParameters = tokenBindingKeyParameters;
    }

    public void setTokenBindingKeyParameters(byte[] tokenBindingParameters) {
        this.tokenBindingKeyParameters =
            ModifiableVariableFactory.safelySetValue(this.tokenBindingKeyParameters, tokenBindingParameters);
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
