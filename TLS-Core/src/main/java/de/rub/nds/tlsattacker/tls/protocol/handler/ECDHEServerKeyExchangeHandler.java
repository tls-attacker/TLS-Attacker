/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler;

import de.rub.nds.tlsattacker.tls.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.ECDHEServerKeyExchangeParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.ECDHEServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.ECDHEServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ECDHEServerKeyExchangeHandler extends ServerKeyExchangeHandler<ECDHEServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger("HANDLER");

    public ECDHEServerKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ECDHEServerKeyExchangeParser getParser(byte[] message, int pointer) {
        return new ECDHEServerKeyExchangeParser(pointer, message, tlsContext.getLastRecordVersion());
    }

    @Override
    public ECDHEServerKeyExchangePreparator getPreparator(ECDHEServerKeyExchangeMessage message) {
        return new ECDHEServerKeyExchangePreparator(tlsContext, message);
    }

    @Override
    public Serializer getSerializer(ECDHEServerKeyExchangeMessage message) {
        return new ECDHEServerKeyExchangeSerializer(message, tlsContext.getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(ECDHEServerKeyExchangeMessage message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
    }
}
