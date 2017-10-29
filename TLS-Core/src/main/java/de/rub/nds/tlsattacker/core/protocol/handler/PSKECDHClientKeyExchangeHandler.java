/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.PSKECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.PSKECDHClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PSKECDHClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PSKECDHClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PSKECDHClientKeyExchangeHandler extends ClientKeyExchangeHandler<PSKECDHClientKeyExchangeMessage> {

    public PSKECDHClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public PSKECDHClientKeyExchangeParser getParser(byte[] message, int pointer) {
        return new PSKECDHClientKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public PSKECDHClientKeyExchangePreparator getPreparator(PSKECDHClientKeyExchangeMessage message) {
        return new PSKECDHClientKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public PSKECDHClientKeyExchangeSerializer getSerializer(PSKECDHClientKeyExchangeMessage message) {
        return new PSKECDHClientKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(PSKECDHClientKeyExchangeMessage message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
        setRecordCipher();
        spawnNewSession();
    }
}
