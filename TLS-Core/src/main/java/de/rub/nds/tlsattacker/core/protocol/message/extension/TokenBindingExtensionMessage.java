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
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 * ATTENTION! This extension is experimental and only registered until
 * 2018-02-04!
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class TokenBindingExtensionMessage extends ExtensionMessage {

    private ModifiableInteger major;
    private ModifiableInteger minor;
    private ModifiableByteArray tokenBindingKeyParameters;

    public TokenBindingExtensionMessage() {
        super(ExtensionType.TOKEN_BINDING);
    }
    
    

    @Override
    public ExtensionHandler getHandler(TlsContext context) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public ModifiableInteger getMajor() {
        return major;
    }

    public void setMajor(ModifiableInteger major) {
        this.major = major;
    }

    public void setMajor(int major) {
        this.major = ModifiableVariableFactory.safelySetValue(this.major, major);
    }

    public ModifiableInteger getMinor() {
        return minor;
    }

    public void setMinor(ModifiableInteger minor) {
        this.minor = minor;
    }

    public void setMinor(int minor) {
        this.minor = ModifiableVariableFactory.safelySetValue(this.minor, minor);
    }

    public ModifiableByteArray getTokenBindingKeyParameters() {
        return tokenBindingKeyParameters;
    }

    public void setTokenBindingKeyParameters(ModifiableByteArray tokenBindingKeyParameters) {
        this.tokenBindingKeyParameters = tokenBindingKeyParameters;
    }

    public void setTokenBindingKeyParameters(byte[] tokenBindingKeyParameters) {
        this.tokenBindingKeyParameters = ModifiableVariableFactory.safelySetValue(this.tokenBindingKeyParameters,
                tokenBindingKeyParameters);
    }

}
