/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.TokenBindingExtensionHandler;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.util.ArrayList;

//TODO LISTLENGTH ANGEBEN!
/**
 * ATTENTION! This extension is experimental and only registered until
 * 2018-02-04!
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class TokenBindingExtensionMessage extends ExtensionMessage {

    private TokenBindingVersion major;
    private TokenBindingVersion minor;
    private TokenBindingKeyParameters[] tokenbindingParameters;
    private int parameterListLength;

    public TokenBindingExtensionMessage() {
        super(ExtensionType.TOKEN_BINDING);
    }

    @Override
    public ExtensionHandler getHandler(TlsContext context) {
        return new TokenBindingExtensionHandler(context);
    }

    public TokenBindingVersion getMajor() {
        return major;
    }

    public void setMajor(TokenBindingVersion major) {
        this.major = major;
    }

    public void setMajor(byte major) {
        this.major = TokenBindingVersion.getExtensionType(major);
    }

    public TokenBindingVersion getMinor() {
        return minor;
    }

    public void setMinor(TokenBindingVersion minor) {
        this.minor = minor;
    }

    public void setMinor(byte minor) {
        this.minor = TokenBindingVersion.getExtensionType(minor);
    }

    public TokenBindingKeyParameters[] getTokenbindingParameters() {
        return tokenbindingParameters;
    }

    public void setTokenbindingParameters(TokenBindingKeyParameters[] tokenbindingParameters) {
        this.tokenbindingParameters = tokenbindingParameters;
    }

    public void setTokenbindingParameters(byte[] parameters) {
        ArrayList<TokenBindingKeyParameters> parameterList = new ArrayList<>();
        for (byte value : parameters) {
            parameterList.add(TokenBindingKeyParameters.getExtensionType(value));
        }
        tokenbindingParameters = parameterList.toArray(tokenbindingParameters);
    }

    public int getParameterListLength() {
        return parameterListLength;
    }

    public void setParameterListLength(int parameterListLength) {
        this.parameterListLength = parameterListLength;
    }

}
