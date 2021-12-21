/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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
import de.rub.nds.tlsattacker.core.protocol.handler.extension.TokenBindingExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.TokenBindingExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.TokenBindingExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.TokenBindingExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.InputStream;

/**
 * This extension is defined in draft-ietf-tokbind-negotiation
 */
public class TokenBindingExtensionMessage extends ExtensionMessage<TokenBindingExtensionMessage> {

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

    @Override
    public TokenBindingExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new TokenBindingExtensionParser(stream, tlsContext.getConfig());
    }

    @Override
    public TokenBindingExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new TokenBindingExtensionPreparator(tlsContext.getChooser(), this, getSerializer(tlsContext));
    }

    @Override
    public TokenBindingExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new TokenBindingExtensionSerializer(this);
    }

    @Override
    public TokenBindingExtensionHandler getHandler(TlsContext tlsContext) {
        return new TokenBindingExtensionHandler(tlsContext);
    }
}
