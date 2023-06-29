/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.TokenBindingExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.TokenBindingExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.TokenBindingExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.TokenBindingExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** This extension is defined in draft-ietf-tokbind-negotiation */
@XmlRootElement(name = "TokenBindingExtension")
public class TokenBindingExtensionMessage extends ExtensionMessage<TokenBindingExtensionMessage> {

    @ModifiableVariableProperty private ModifiableByteArray tokenBindingVersion;
    @ModifiableVariableProperty private ModifiableByteArray tokenBindingKeyParameters;
    private ModifiableInteger parameterListLength;

    public TokenBindingExtensionMessage() {
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
                ModifiableVariableFactory.safelySetValue(
                        this.tokenBindingVersion, tokenBindingVersion);
    }

    public ModifiableByteArray getTokenBindingKeyParameters() {
        return tokenBindingKeyParameters;
    }

    public void setTokenBindingKeyParameters(ModifiableByteArray tokenBindingKeyParameters) {
        this.tokenBindingKeyParameters = tokenBindingKeyParameters;
    }

    public void setTokenBindingKeyParameters(byte[] tokenBindingParameters) {
        this.tokenBindingKeyParameters =
                ModifiableVariableFactory.safelySetValue(
                        this.tokenBindingKeyParameters, tokenBindingParameters);
    }

    public ModifiableInteger getParameterListLength() {
        return parameterListLength;
    }

    public void setParameterListLength(ModifiableInteger parameterListLength) {
        this.parameterListLength = parameterListLength;
    }

    public void setParameterListLength(int parameterListLength) {
        this.parameterListLength =
                ModifiableVariableFactory.safelySetValue(
                        this.parameterListLength, parameterListLength);
    }

    @Override
    public TokenBindingExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new TokenBindingExtensionParser(stream, tlsContext);
    }

    @Override
    public TokenBindingExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new TokenBindingExtensionPreparator(tlsContext.getChooser(), this);
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
