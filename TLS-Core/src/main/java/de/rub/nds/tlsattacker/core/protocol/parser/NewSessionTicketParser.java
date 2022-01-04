/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;

public class NewSessionTicketParser extends HandshakeMessageParser<NewSessionTicketMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ConnectionEndType talkingConnectionEndType;

    public NewSessionTicketParser(InputStream stream, ProtocolVersion version, TlsContext tlsContext,
                                  ConnectionEndType talkingConnectionEndType) {
        super(stream, HandshakeMessageType.NEW_SESSION_TICKET, version, tlsContext);
        this.talkingConnectionEndType = talkingConnectionEndType;
    }

    @Override
    protected void parseHandshakeMessageContent(NewSessionTicketMessage msg) {
        LOGGER.debug("Parsing NewSessionTicket");
        if (getVersion().isTLS13()) {
            parseLifetime(msg);
            parseAgeAdd(msg);
            parseNonceLength(msg);
            parseNonce(msg);
            parseIdentityLength(msg);
            parseIdentity(msg);
            if (hasExtensionLengthField(msg)) {
                parseExtensionLength(msg);
                if (hasExtensions(msg)) {
                    parseExtensionBytes(msg, getVersion(), talkingConnectionEndType, false);
                }
            }
        } else {
            parseLifetime(msg);
            parseIdentityLength(msg);
            parseIdentity(msg);
        }
    }

    private void parseLifetime(NewSessionTicketMessage msg) {
        msg.setTicketLifetimeHint(parseIntField(HandshakeByteLength.NEWSESSIONTICKET_LIFETIMEHINT_LENGTH));
        LOGGER.debug("TicketLifetimeHint:" + msg.getTicketLifetimeHint().getValue());
    }

    private void parseAgeAdd(NewSessionTicketMessage msg) {
        msg.getTicket().setTicketAgeAdd(parseByteArrayField(HandshakeByteLength.TICKET_AGE_ADD_LENGTH));
        LOGGER.debug("TicketAgeAdd:" + ArrayConverter.bytesToHexString(msg.getTicket().getTicketAgeAdd().getValue()));
    }

    private void parseNonceLength(NewSessionTicketMessage msg) {
        msg.getTicket().setTicketNonceLength(parseIntField(HandshakeByteLength.TICKET_NONCE_LENGTH));
        LOGGER.debug("TicketNonceLength: " + msg.getTicket().getTicketNonceLength().getValue());
    }

    private void parseNonce(NewSessionTicketMessage msg) {
        msg.getTicket().setTicketNonce(parseByteArrayField(msg.getTicket().getTicketNonceLength().getValue()));
        LOGGER.debug("TicketNonce:" + ArrayConverter.bytesToHexString(msg.getTicket().getTicketNonce().getValue()));
    }

    private void parseIdentityLength(NewSessionTicketMessage msg) {
        msg.getTicket().setIdentityLength(parseIntField(ExtensionByteLength.PSK_IDENTITY_LENGTH));
        LOGGER.debug("IdentityLength: " + msg.getTicket().getIdentityLength().getValue());
    }

    private void parseIdentity(NewSessionTicketMessage msg) {
        msg.getTicket().setIdentity(parseByteArrayField(msg.getTicket().getIdentityLength().getValue()));
        LOGGER.debug("Identity:" + ArrayConverter.bytesToHexString(msg.getTicket().getIdentity().getValue()));
    }

}
