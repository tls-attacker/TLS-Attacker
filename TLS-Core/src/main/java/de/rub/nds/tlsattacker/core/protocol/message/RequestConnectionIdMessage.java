/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.RequestConnectionIdHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.RequestConnectionIdParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.RequestConnectionIdPreperator;
import de.rub.nds.tlsattacker.core.protocol.serializer.RequestConnectionIdSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.Objects;

@XmlRootElement(name = "RequestConnectionId")
public class RequestConnectionIdMessage extends HandshakeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.NONE)
    ModifiableInteger numberOfConnectionIds;

    public RequestConnectionIdMessage() {
        super(HandshakeMessageType.REQUEST_CONNECTION_ID);
    }

    public ModifiableInteger getNumberOfConnectionIds() {
        return numberOfConnectionIds;
    }

    public void setNumberOfConnectionIds(ModifiableInteger numberOfConnectionIds) {
        this.numberOfConnectionIds = numberOfConnectionIds;
    }

    public void setNumberOfConnectionIds(Integer numberOfConnectionIds) {
        this.numberOfConnectionIds =
                ModifiableVariableFactory.safelySetValue(
                        this.numberOfConnectionIds, numberOfConnectionIds);
    }

    @Override
    public RequestConnectionIdParser getParser(Context context, InputStream stream) {
        return new RequestConnectionIdParser(stream, context.getTlsContext());
    }

    @Override
    public RequestConnectionIdPreperator getPreparator(Context context) {
        return new RequestConnectionIdPreperator(context.getChooser(), this);
    }

    @Override
    public RequestConnectionIdSerializer getSerializer(Context context) {
        return new RequestConnectionIdSerializer(this);
    }

    @Override
    public RequestConnectionIdHandler getHandler(Context context) {
        return new RequestConnectionIdHandler(context.getTlsContext());
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 67 * hash + Objects.hashCode(this.numberOfConnectionIds);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final RequestConnectionIdMessage other = (RequestConnectionIdMessage) obj;
        return Objects.equals(this.numberOfConnectionIds, other.numberOfConnectionIds);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("RequestConnectionId:");
        sb.append("\n  NumberOfConnectionIds: ");
        if (numberOfConnectionIds != null && numberOfConnectionIds.getValue() != null) {
            sb.append(numberOfConnectionIds.getValue());
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "RCID";
    }
}
