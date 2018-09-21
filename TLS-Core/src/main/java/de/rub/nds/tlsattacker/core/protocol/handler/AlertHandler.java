/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.AlertParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.AlertPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.AlertSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AlertHandler extends ProtocolMessageHandler<AlertMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AlertHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public AlertParser getParser(byte[] message, int pointer) {
        return new AlertParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public AlertPreparator getPreparator(AlertMessage message) {
        return new AlertPreparator(tlsContext.getChooser(), message);
    }

    @Override
    public AlertSerializer getSerializer(AlertMessage message) {
        return new AlertSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(AlertMessage message) {
        if (tlsContext.getTalkingConnectionEndType() == tlsContext.getChooser().getMyConnectionPeer()
                && AlertLevel.FATAL.getValue() == message.getLevel().getValue()) {
            LOGGER.debug("Setting received Fatal Alert in Context");
            tlsContext.setReceivedFatalAlert(true);
        }
    }
}
