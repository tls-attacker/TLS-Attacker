/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler;

import de.rub.nds.tlsattacker.tls.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.ApplicationMessageParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.Parser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.ApplicationMessagePreparator;
import de.rub.nds.tlsattacker.tls.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.ApplicationMessageSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ApplicationHandler extends ProtocolMessageHandler<ApplicationMessage> {

    private static final Logger LOGGER = LogManager.getLogger("HANDLER");
    
    public ApplicationHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ApplicationMessageParser getParser(byte[] message, int pointer) {
        return new ApplicationMessageParser(pointer, message, tlsContext.getLastRecordVersion());
    }

    @Override
    public Preparator getPreparator(ApplicationMessage message) {
        return new ApplicationMessagePreparator(tlsContext, message);
    }

    @Override
    public Serializer getSerializer(ApplicationMessage message) {
        return new ApplicationMessageSerializer(message, tlsContext.getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(ApplicationMessage message) {
        // TLSContext does not change when sending or receiving
        // ApplicationMessages
    }

}