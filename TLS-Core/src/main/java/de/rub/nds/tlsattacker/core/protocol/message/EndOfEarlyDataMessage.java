/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import java.io.InputStream;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * RFC draft-ietf-tls-tls13-21
 */
@XmlRootElement(name = "EndOfEarlyData")
public class EndOfEarlyDataMessage extends HandshakeMessage {

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

}
