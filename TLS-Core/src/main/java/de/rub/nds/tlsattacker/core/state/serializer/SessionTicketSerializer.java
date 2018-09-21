/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.state.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.core.state.SessionTicket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SessionTicketSerializer extends Serializer<SessionTicket> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SessionTicket sessionTicket;

    public SessionTicketSerializer(SessionTicket sessionTicket) {
        this.sessionTicket = sessionTicket;
    }

    @Override
    protected byte[] serializeBytes() {
        LOGGER.debug("Serializing SessionTicket");
        writeKeyName(sessionTicket);
        writeIV(sessionTicket);
        writeEncryptedState(sessionTicket);
        writeMAC(sessionTicket);
        return getAlreadySerialized();
    }

    private void writeKeyName(SessionTicket sessionTicket) {
        appendBytes(sessionTicket.getKeyName().getValue());
        LOGGER.debug("KeyName: " + ArrayConverter.bytesToHexString(sessionTicket.getKeyName().getValue()));
    }

    private void writeIV(SessionTicket sessionTicket) {
        appendBytes(sessionTicket.getIV().getValue());
        LOGGER.debug("IV: " + ArrayConverter.bytesToHexString(sessionTicket.getIV().getValue()));
    }

    private void writeEncryptedState(SessionTicket sessionTicket) {
        appendBytes(sessionTicket.getEncryptedState().getValue());
        LOGGER.debug("EncryptedState: "
                + ArrayConverter.bytesToHexString(sessionTicket.getEncryptedState().getValue(), true, true));
    }

    private void writeMAC(SessionTicket sessionTicket) {
        appendBytes(sessionTicket.getMAC().getValue());
        LOGGER.debug("MAC: " + ArrayConverter.bytesToHexString(sessionTicket.getMAC().getValue()));
    }

}
