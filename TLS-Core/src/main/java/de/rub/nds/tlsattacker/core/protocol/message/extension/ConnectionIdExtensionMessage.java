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
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ConnectionIdExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ConnectionIdExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ConnectionIdExtensionPreperator;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ConnectionIdExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** Class representing a Connection ID Extension Message, as defined as in RFC9146 */
@XmlRootElement(name = "ConnectionIdExtension")
public class ConnectionIdExtensionMessage extends ExtensionMessage<ConnectionIdExtensionMessage> {

    public ConnectionIdExtensionMessage() {
        super(ExtensionType.CONNECTION_ID);
    }

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.NONE)
    private ModifiableByteArray connectionId;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger connectionIdLength;

    public ModifiableByteArray getConnectionId() {
        return connectionId;
    }

    public ModifiableInteger getConnectionIdLength() {
        return connectionIdLength;
    }

    public void setConnectionId(ModifiableByteArray connectionId) {
        this.connectionId = connectionId;
    }

    public void setConnectionId(byte[] array) {
        this.connectionId = ModifiableVariableFactory.safelySetValue(connectionId, array);
    }

    public void setConnectionIdLength(ModifiableInteger connectionIdLength) {
        this.connectionIdLength = connectionIdLength;
    }

    public void setConnectionIdLength(int length) {
        this.connectionIdLength =
                ModifiableVariableFactory.safelySetValue(connectionIdLength, length);
    }

    @Override
    public ExtensionHandler<ConnectionIdExtensionMessage> getHandler(TlsContext tlsContext) {
        return new ConnectionIdExtensionHandler(tlsContext);
    }

    @Override
    public ExtensionSerializer<ConnectionIdExtensionMessage> getSerializer(TlsContext tlsContext) {
        return new ConnectionIdExtensionSerializer(this);
    }

    @Override
    public ExtensionPreparator<ConnectionIdExtensionMessage> getPreparator(TlsContext tlsContext) {
        return new ConnectionIdExtensionPreperator(tlsContext.getChooser(), this);
    }

    @Override
    public ExtensionParser<ConnectionIdExtensionMessage> getParser(
            TlsContext tlsContext, InputStream stream) {
        return new ConnectionIdExtensionParser(stream, tlsContext);
    }
}
