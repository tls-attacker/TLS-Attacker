/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NewSessionTicketParser extends HandshakeMessageParser<NewSessionTicketMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public NewSessionTicketParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(NewSessionTicketMessage msg) {
        LOGGER.debug("Parsing NewSessionTicket");
        if (getVersion().isTLS13()) {
            parseLifetime(msg);
            parseAgeAdd(msg);
            parseNonceLength(msg);
            parseNonce(msg);
            parseIdentityLength(msg);
            parseIdentity(msg);
            if (hasExtensionLengthField()) {
                parseExtensionLength(msg);
                if (hasExtensions(msg)) {
                    parseExtensionBytes(msg, false);
                }
            }
        } else {
            parseLifetime(msg);
            parseIdentityLength(msg);
            parseIdentity(msg);
        }
    }

    private void parseLifetime(NewSessionTicketMessage msg) {
        msg.setTicketLifetimeHint(
                parseIntField(HandshakeByteLength.NEWSESSIONTICKET_LIFETIMEHINT_LENGTH));
        LOGGER.debug("TicketLifetimeHint: " + msg.getTicketLifetimeHint().getValue());
    }

    private void parseAgeAdd(NewSessionTicketMessage msg) {
        msg.getTicket()
                .setTicketAgeAdd(parseByteArrayField(HandshakeByteLength.TICKET_AGE_ADD_LENGTH));
        LOGGER.debug("TicketAgeAdd: {}", msg.getTicket().getTicketAgeAdd().getValue());
    }

    private void parseNonceLength(NewSessionTicketMessage msg) {
        msg.getTicket()
                .setTicketNonceLength(parseIntField(HandshakeByteLength.TICKET_NONCE_LENGTH));
        LOGGER.debug("TicketNonceLength: " + msg.getTicket().getTicketNonceLength().getValue());
    }

    private void parseNonce(NewSessionTicketMessage msg) {
        msg.getTicket()
                .setTicketNonce(
                        parseByteArrayField(msg.getTicket().getTicketNonceLength().getValue()));
        LOGGER.debug("TicketNonce: {}", msg.getTicket().getTicketNonce().getValue());
    }

    private void parseIdentityLength(NewSessionTicketMessage msg) {
        msg.getTicket().setIdentityLength(parseIntField(ExtensionByteLength.PSK_IDENTITY_LENGTH));
        LOGGER.debug("IdentityLength: " + msg.getTicket().getIdentityLength().getValue());
    }

    private void parseIdentity(NewSessionTicketMessage msg) {
        msg.getTicket()
                .setIdentity(parseByteArrayField(msg.getTicket().getIdentityLength().getValue()));
        LOGGER.debug("Identity: {}", msg.getTicket().getIdentity().getValue());
    }
}
