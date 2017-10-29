/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.PSKServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.PSKServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PSKServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PSKServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PSKServerKeyExchangeHandler extends ServerKeyExchangeHandler<PSKServerKeyExchangeMessage> {

    public PSKServerKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public PSKServerKeyExchangeParser getParser(byte[] message, int pointer) {
        return new PSKServerKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public PSKServerKeyExchangePreparator getPreparator(PSKServerKeyExchangeMessage message) {
        return new PSKServerKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public PSKServerKeyExchangeSerializer getSerializer(PSKServerKeyExchangeMessage message) {
        return new PSKServerKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(PSKServerKeyExchangeMessage message) {
    }
}
