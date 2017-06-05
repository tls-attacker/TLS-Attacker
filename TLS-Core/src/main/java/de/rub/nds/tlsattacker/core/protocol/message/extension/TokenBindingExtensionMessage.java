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
    private ModifiableByte majorTokenbindingVersion;
    @ModifiableVariableProperty
    private ModifiableByte minorTokenbindingVersion;
    @ModifiableVariableProperty
    private ModifiableByteArray tokenbindingKeyParameters;
    private int parameterListLength;

    public TokenBindingExtensionMessage() {
        super(ExtensionType.TOKEN_BINDING);
    }

    @Override
    public ExtensionHandler getHandler(TlsContext context) {
        return new TokenBindingExtensionHandler(context);
    }

    public ModifiableByte getMajorTokenbindingVersion() {
        return majorTokenbindingVersion;
    }

    public void setMajorTokenbindingVersion(ModifiableByte majorTokenbindingVersion) {
        this.majorTokenbindingVersion = majorTokenbindingVersion;
    }

    public void setMajorTokenbindingVersion(byte major) {
        this.majorTokenbindingVersion = ModifiableVariableFactory.safelySetValue(this.majorTokenbindingVersion, major);
    }

    public ModifiableByte getMinorTokenbindingVersion() {
        return minorTokenbindingVersion;
    }

    public void setMinorTokenbindingVersion(ModifiableByte minorTokenbindingVersion) {
        this.minorTokenbindingVersion = minorTokenbindingVersion;
    }

    public void setMinorTokenbindingVersion(byte minor) {
        this.minorTokenbindingVersion = ModifiableVariableFactory.safelySetValue(this.minorTokenbindingVersion, minor);
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
