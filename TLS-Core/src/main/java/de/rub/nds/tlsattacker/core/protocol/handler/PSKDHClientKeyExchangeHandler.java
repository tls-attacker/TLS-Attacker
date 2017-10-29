/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.PSKDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.PSKDHClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PSKDHClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PSKDHClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PSKDHClientKeyExchangeHandler extends ClientKeyExchangeHandler<PSKDHClientKeyExchangeMessage> {

    public PSKDHClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public PSKDHClientKeyExchangeParser getParser(byte[] message, int pointer) {
        return new PSKDHClientKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public PSKDHClientKeyExchangePreparator getPreparator(PSKDHClientKeyExchangeMessage message) {
        return new PSKDHClientKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public PSKDHClientKeyExchangeSerializer getSerializer(PSKDHClientKeyExchangeMessage message) {
        return new PSKDHClientKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(PSKDHClientKeyExchangeMessage message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
        setRecordCipher();
        spawnNewSession();
    }
}
