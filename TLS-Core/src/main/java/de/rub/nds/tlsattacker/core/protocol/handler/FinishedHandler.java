/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.FinishedMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.FinishedMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.FinishedMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class FinishedHandler extends HandshakeMessageHandler<FinishedMessage> {

    public FinishedHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public FinishedMessageParser getParser(byte[] message, int pointer) {
        return new FinishedMessageParser(pointer, message, tlsContext.getLastRecordVersion());
    }

    @Override
    public FinishedMessagePreparator getPreparator(FinishedMessage message) {
        return new FinishedMessagePreparator(tlsContext, message);
    }

    @Override
    public FinishedMessageSerializer getSerializer(FinishedMessage message) {
        return new FinishedMessageSerializer(message, tlsContext.getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(FinishedMessage message) {
        // Nothing to do
    }

}
