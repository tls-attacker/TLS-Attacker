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
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.RequestConnectionIdHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.RequestConnectionIdParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.RequestConnectionIdPreperator;
import de.rub.nds.tlsattacker.core.protocol.serializer.RequestConnectionIdSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement(name = "RequestConnectionId")
public class RequestConnectionIdMessage extends HandshakeMessage {

    ModifiableInteger numberOfConnectionIds;

    public RequestConnectionIdMessage() {
        super(HandshakeMessageType.REQUEST_CONNECTION_ID);
    }

    public ModifiableInteger getNumberOfConnectionIds() {
        return numberOfConnectionIds;
    }

    public void setNumberOfConnectionIds(Integer numberOfConnectionIds) {
        this.numberOfConnectionIds =
                ModifiableVariableFactory.safelySetValue(
                        this.numberOfConnectionIds, numberOfConnectionIds);
    }

    @Override
    public String toShortString() {
        return null;
    }

    @Override
    public RequestConnectionIdParser getParser(TlsContext tlsContext, InputStream stream) {
        return new RequestConnectionIdParser(stream, tlsContext);
    }

    @Override
    public RequestConnectionIdPreperator getPreparator(TlsContext tlsContext) {
        return new RequestConnectionIdPreperator(tlsContext.getChooser(), this);
    }

    @Override
    public RequestConnectionIdSerializer getSerializer(TlsContext tlsContext) {
        return new RequestConnectionIdSerializer(this);
    }

    @Override
    public RequestConnectionIdHandler getHandler(TlsContext tlsContext) {
        return new RequestConnectionIdHandler(tlsContext);
    }
}
