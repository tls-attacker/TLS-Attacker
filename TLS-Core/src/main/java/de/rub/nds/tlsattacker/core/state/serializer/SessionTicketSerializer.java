/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.state.serializer;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
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
        writeEncryptedStateLength(sessionTicket);
        writeEncryptedState(sessionTicket);
        writeMAC(sessionTicket);
        return getAlreadySerialized();
    }

    private void writeKeyName(SessionTicket sessionTicket) {
        appendBytes(sessionTicket.getKeyName().getValue());
        LOGGER.debug("KeyName: {}", sessionTicket.getKeyName().getValue());
    }

    private void writeIV(SessionTicket sessionTicket) {
        appendBytes(sessionTicket.getIV().getValue());
        LOGGER.debug("IV: {}", sessionTicket.getIV().getValue());
    }

    private void writeEncryptedStateLength(SessionTicket sessionTicket) {
        appendInt(
                sessionTicket.getEncryptedStateLength().getValue(),
                ExtensionByteLength.ENCRYPTED_SESSION_TICKET_STATE_LENGTH);
    }

    private void writeEncryptedState(SessionTicket sessionTicket) {
        appendBytes(sessionTicket.getEncryptedState().getValue());
        LOGGER.debug("EncryptedState: {}", sessionTicket.getEncryptedState().getValue());
    }

    private void writeMAC(SessionTicket sessionTicket) {
        appendBytes(sessionTicket.getMAC().getValue());
        LOGGER.debug("MAC: {}", sessionTicket.getMAC().getValue());
    }
}
