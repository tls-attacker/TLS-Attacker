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
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.EndOfEarlyDataHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.EndOfEarlyDataParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.EndOfEarlyDataPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.EndOfEarlyDataSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** RFC draft-ietf-tls-tls13-21 */
@XmlRootElement(name = "EndOfEarlyData")
public class EndOfEarlyDataMessage extends HandshakeMessage<EndOfEarlyDataMessage> {

    public EndOfEarlyDataMessage() {
        super(HandshakeMessageType.END_OF_EARLY_DATA);
    }

    @Override
    public EndOfEarlyDataHandler getHandler(TlsContext tlsContext) {
        return new EndOfEarlyDataHandler(tlsContext);
    }

    @Override
    public EndOfEarlyDataParser getParser(TlsContext tlsContext, InputStream stream) {
        return new EndOfEarlyDataParser(stream, tlsContext);
    }

    @Override
    public EndOfEarlyDataPreparator getPreparator(TlsContext tlsContext) {
        return new EndOfEarlyDataPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public EndOfEarlyDataSerializer getSerializer(TlsContext tlsContext) {
        return new EndOfEarlyDataSerializer(this);
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
