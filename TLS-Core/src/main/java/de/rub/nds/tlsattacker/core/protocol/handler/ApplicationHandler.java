/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ApplicationMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ApplicationMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ApplicationMessageSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ApplicationHandler extends ProtocolMessageHandler<ApplicationMessage> {

    public ApplicationHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ApplicationMessageParser getParser(byte[] message, int pointer) {
        return new ApplicationMessageParser(pointer, message, tlsContext.getLastRecordVersion());
    }

    @Override
    public ApplicationMessagePreparator getPreparator(ApplicationMessage message) {
        return new ApplicationMessagePreparator(tlsContext, message);
    }

    @Override
    public ApplicationMessageSerializer getSerializer(ApplicationMessage message) {
        return new ApplicationMessageSerializer(message, tlsContext.getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(ApplicationMessage message) {
        // TLSContext does not change when sending or receiving
        // ApplicationMessages
    }

}
