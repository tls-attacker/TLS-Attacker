/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.EndOfEarlyDataHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.EndOfEarlyDataParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.EndOfEarlyDataPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.EndOfEarlyDataSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** RFC draft-ietf-tls-tls13-21 */
@XmlRootElement(name = "EndOfEarlyData")
public class EndOfEarlyDataMessage extends HandshakeMessage {

    public EndOfEarlyDataMessage() {
        super(HandshakeMessageType.END_OF_EARLY_DATA);
    }

    @Override
    public EndOfEarlyDataHandler getHandler(Context context) {
        return new EndOfEarlyDataHandler(context.getTlsContext());
    }

    @Override
    public EndOfEarlyDataParser getParser(Context context, InputStream stream) {
        return new EndOfEarlyDataParser(stream, context.getTlsContext());
    }

    @Override
    public EndOfEarlyDataPreparator getPreparator(Context context) {
        return new EndOfEarlyDataPreparator(context.getChooser(), this);
    }

    @Override
    public EndOfEarlyDataSerializer getSerializer(Context context) {
        return new EndOfEarlyDataSerializer(this);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("EndOfEarlyDataMessage: <empty>");
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "EOED";
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
        return true;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        return hash;
    }
}
