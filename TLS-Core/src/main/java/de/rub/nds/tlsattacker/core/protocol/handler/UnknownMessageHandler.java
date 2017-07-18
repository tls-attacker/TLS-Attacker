/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.UnknownMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.UnknownMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.UnknownMessageSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.DefaultChooser;

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
        return new UnknownMessageParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public UnknownMessagePreparator getPreparator(UnknownMessage message) {
        return new UnknownMessagePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public UnknownMessageSerializer getSerializer(UnknownMessage message) {
        return new UnknownMessageSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(UnknownMessage message) {
        // Nothing to do
    }

}
