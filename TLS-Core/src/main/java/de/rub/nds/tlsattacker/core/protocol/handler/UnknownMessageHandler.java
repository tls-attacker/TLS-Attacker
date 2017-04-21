/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;
import de.rub.nds.tlsattacker.core.protocol.parser.UnknownMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.UnknownMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.UnknownMessageSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class UnknownMessageHandler extends ProtocolMessageHandler<UnknownMessage> {

    public UnknownMessageHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public UnknownMessageParser getParser(byte[] message, int pointer) {
        return new UnknownMessageParser(pointer, message, tlsContext.getLastRecordVersion());
    }

    @Override
    public UnknownMessagePreparator getPreparator(UnknownMessage message) {
        return new UnknownMessagePreparator(tlsContext, message);
    }

    @Override
    public UnknownMessageSerializer getSerializer(UnknownMessage message) {
        return new UnknownMessageSerializer(message, tlsContext.getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(UnknownMessage message) {
        // Nothing to do
    }

}
