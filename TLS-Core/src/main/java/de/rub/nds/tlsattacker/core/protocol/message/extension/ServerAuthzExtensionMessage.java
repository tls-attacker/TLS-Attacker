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
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ServerAuthzExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ServerAuthzExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ServerAuthzExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ServerAuthzExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.InputStream;

/**
 * This extension is defined in RFC5878
 */
public class ServerAuthzExtensionMessage extends ExtensionMessage<ServerAuthzExtensionMessage> {

    @ModifiableVariableProperty
    private ModifiableInteger authzFormatListLength;
    @ModifiableVariableProperty
    private ModifiableByteArray authzFormatList;

    public ServerAuthzExtensionMessage() {
        super(ExtensionType.SERVER_AUTHZ);
    }

    public ServerAuthzExtensionMessage(Config config) {
        super(ExtensionType.SERVER_AUTHZ);
    }

    public ModifiableInteger getAuthzFormatListLength() {
        return authzFormatListLength;
    }

    public void setAuthzFormatListLength(ModifiableInteger authzFormatListLength) {
        this.authzFormatListLength = authzFormatListLength;
    }

    public void setAuthzFormatListLength(int authzFormatListLength) {
        this.authzFormatListLength =
            ModifiableVariableFactory.safelySetValue(this.authzFormatListLength, authzFormatListLength);
    }

    public ModifiableByteArray getAuthzFormatList() {
        return authzFormatList;
    }

    public void setAuthzFormatList(ModifiableByteArray authzFormatList) {
        this.authzFormatList = authzFormatList;
    }

    public void setAuthzFormatList(byte[] authzFormatList) {
        this.authzFormatList = ModifiableVariableFactory.safelySetValue(this.authzFormatList, authzFormatList);
    }

    @Override
    public ServerAuthzExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new ServerAuthzExtensionParser(stream, tlsContext.getConfig());
    }

    @Override
    public ServerAuthzExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new ServerAuthzExtensionPreparator(tlsContext.getChooser(), this, getSerializer(tlsContext));
    }

    @Override
    public ServerAuthzExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new ServerAuthzExtensionSerializer(this);
    }

    @Override
    public ServerAuthzExtensionHandler getHandler(TlsContext tlsContext) {
        return new ServerAuthzExtensionHandler(tlsContext);
    }
}
