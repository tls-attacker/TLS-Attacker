/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ConnectionIdUsage;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.NewConnectionIdHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.NewConnectionIdParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.NewConnectionIdPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.NewConnectionIdSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement(name = "NewConnectionId")
public class NewConnectionIdMessage extends HandshakeMessage {

    private ConnectionIdUsage usage;
    private ModifiableInteger connectionIdsLength;
    private ModifiableByteArray connectionIds;

    public NewConnectionIdMessage() {
        super(HandshakeMessageType.NEW_CONNECTION_ID);
    }

    @Override
    public String toShortString() {
        return null;
    }

    @Override
    public NewConnectionIdParser getParser(TlsContext tlsContext, InputStream stream) {
        return new NewConnectionIdParser(stream, tlsContext);
    }

    @Override
    public NewConnectionIdPreparator getPreparator(TlsContext tlsContext) {
        return new NewConnectionIdPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public NewConnectionIdSerializer getSerializer(TlsContext tlsContext) {
        return new NewConnectionIdSerializer(this);
    }

    @Override
    public NewConnectionIdHandler getHandler(TlsContext tlsContext) {
        return new NewConnectionIdHandler(tlsContext);
    }

    public ConnectionIdUsage getUsage() {
        return usage;
    }

    public void setUsage(ConnectionIdUsage usage) {
        this.usage = usage;
    }

    public ModifiableInteger getConnectionIdsLength() {
        return connectionIdsLength;
    }

    public void setConnectionIdsLength(Integer connectionIdsLength) {
        this.connectionIdsLength =
                ModifiableVariableFactory.safelySetValue(
                        this.connectionIdsLength, connectionIdsLength);
    }

    public ModifiableByteArray getConnectionIds() {
        return connectionIds;
    }

    public void setConnectionIds(byte[] connectionIds) {
        this.connectionIds =
                ModifiableVariableFactory.safelySetValue(this.connectionIds, connectionIds);
    }
}
