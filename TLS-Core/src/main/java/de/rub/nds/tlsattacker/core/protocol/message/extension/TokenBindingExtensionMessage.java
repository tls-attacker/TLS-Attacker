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
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.TokenBindingExtensionHandler;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

//TODO LISTLENGTH ANGEBEN!
/**
 * ATTENTION! This extension is experimental and only registered until
 * 2018-02-04!
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class TokenBindingExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty
    private ModifiableByte major;
    @ModifiableVariableProperty
    private ModifiableByte minor;
    @ModifiableVariableProperty
    private ModifiableByteArray tokenbindingParameters;
    private int parameterListLength;

    public TokenBindingExtensionMessage() {
        super(ExtensionType.TOKEN_BINDING);
    }

    @Override
    public ExtensionHandler getHandler(TlsContext context) {
        return new TokenBindingExtensionHandler(context);
    }

    public ModifiableByte getMajor() {
        return major;
    }

    public void setMajor(ModifiableByte major) {
        this.major = major;
    }

    public void setMajor(byte major) {
        this.major = ModifiableVariableFactory.safelySetValue(this.major, major);
    }

    public ModifiableByte getMinor() {
        return minor;
    }

    public void setMinor(ModifiableByte minor) {
        this.minor = minor;
    }

    public void setMinor(byte minor) {
        this.minor = ModifiableVariableFactory.safelySetValue(this.minor, minor);
    }

    public ModifiableByteArray getTokenbindingParameters() {
        return tokenbindingParameters;
    }

    public void setTokenbindingParameters(ModifiableByteArray tokenbindingParameters) {
        this.tokenbindingParameters = tokenbindingParameters;
    }

    public void setTokenbindingParameters(byte[] tokenbindingParameters) {
        this.tokenbindingParameters = ModifiableVariableFactory.safelySetValue(this.tokenbindingParameters,
                tokenbindingParameters);
    }

    public int getParameterListLength() {
        return parameterListLength;
    }

    public void setParameterListLength(int parameterListLength) {
        this.parameterListLength = parameterListLength;
    }

}
