/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler;

import de.rub.nds.tlsattacker.tls.constants.AlertLevel;
import de.rub.nds.tlsattacker.tls.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.AlertParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.AlertPreparator;
import de.rub.nds.tlsattacker.tls.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.AlertSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class AlertHandler extends ProtocolMessageHandler<AlertMessage> {

    private static final Logger LOGGER = LogManager.getLogger("HANDLER");

    public AlertHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public AlertParser getParser(byte[] message, int pointer) {
        return new AlertParser(pointer, message, tlsContext.getLastRecordVersion());
    }

    @Override
    public Preparator getPreparator(AlertMessage message) {
        return new AlertPreparator(tlsContext, message);
    }

    @Override
    public Serializer getSerializer(AlertMessage message) {
        return new AlertSerializer(message, tlsContext.getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(AlertMessage message) {
        if (tlsContext.getTalkingConnectionEnd() == tlsContext.getConfig().getMyConnectionEnd()
                && AlertLevel.FATAL.getValue() == message.getLevel().getValue()) {
            LOGGER.debug("Setting received Fatal Alert in Context");
            tlsContext.setReceivedFatalAlert(true);
        }
    }
}
