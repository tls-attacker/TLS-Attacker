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
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ClientAuthzExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ClientAuthzExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ClientAuthzExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ClientAuthzExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** This extension is defined in RFC5878 */
@XmlRootElement(name = "ClientAuthorizationExtension")
public class ClientAuthzExtensionMessage extends ExtensionMessage<ClientAuthzExtensionMessage> {

    @ModifiableVariableProperty ModifiableInteger authzFormatListLength;
    @ModifiableVariableProperty ModifiableByteArray authzFormatList;

    public ClientAuthzExtensionMessage() {
        super(ExtensionType.CLIENT_AUTHZ);
    }

    public ModifiableInteger getAuthzFormatListLength() {
        return authzFormatListLength;
    }

    public void setAuthzFormatListLength(ModifiableInteger authzFormatListLength) {
        this.authzFormatListLength = authzFormatListLength;
    }

    public void setAuthzFormatListLength(int authzFormatListLength) {
        this.authzFormatListLength =
                ModifiableVariableFactory.safelySetValue(
                        this.authzFormatListLength, authzFormatListLength);
    }

    public ModifiableByteArray getAuthzFormatList() {
        return authzFormatList;
    }

    public void setAuthzFormatList(ModifiableByteArray authzFormatList) {
        this.authzFormatList = authzFormatList;
    }

    public void setAuthzFormatList(byte[] authzFormatList) {
        this.authzFormatList =
                ModifiableVariableFactory.safelySetValue(this.authzFormatList, authzFormatList);
    }

    @Override
    public ClientAuthzExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new ClientAuthzExtensionParser(stream, tlsContext);
    }

    @Override
    public ClientAuthzExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new ClientAuthzExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public ClientAuthzExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new ClientAuthzExtensionSerializer(this);
    }

    @Override
    public ClientAuthzExtensionHandler getHandler(TlsContext tlsContext) {
        return new ClientAuthzExtensionHandler(tlsContext);
    }
}
