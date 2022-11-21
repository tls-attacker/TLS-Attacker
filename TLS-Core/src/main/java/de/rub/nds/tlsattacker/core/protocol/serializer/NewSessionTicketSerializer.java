/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NewSessionTicketSerializer extends HandshakeMessageSerializer<NewSessionTicketMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final NewSessionTicketMessage msg;

    /**
     * Constructor for the NewSessionTicketMessageSerializer
     *
     * @param message
     *                Message that should be serialized
     * @param version
     *                Version of the Protocol
     */
    public NewSessionTicketSerializer(NewSessionTicketMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing NewSessionTicketMessage");
        writeLifetimeHint(msg);
        if (version.isTLS13()) {
            // TLS 1.3
            writeTicketAgeAdd(msg);
            writeTicketNonceLength(msg);
            writeTicketNonce(msg);
            writeTicketIdentityLength(msg);
            writeTicketIdentity(msg);
            writeExtensions();
        } else {
            writeTicketLength(msg);
            writeTicket(msg);
        }

        return getAlreadySerialized();
    }

    private void writeLifetimeHint(NewSessionTicketMessage msg) {
        appendBytes(ArrayConverter.longToBytes(msg.getTicketLifetimeHint().getValue(),
            HandshakeByteLength.NEWSESSIONTICKET_LIFETIMEHINT_LENGTH));
        LOGGER.debug("LifetimeHint: "
            + ArrayConverter.bytesToHexString(ArrayConverter.longToBytes(msg.getTicketLifetimeHint().getValue(),
                HandshakeByteLength.NEWSESSIONTICKET_LIFETIMEHINT_LENGTH)));
    }

    private void writeTicketLength(NewSessionTicketMessage msg) {
        appendBytes(ArrayConverter.intToBytes(msg.getTicket().getIdentityLength().getValue(),
            HandshakeByteLength.NEWSESSIONTICKET_TICKET_LENGTH));
        LOGGER.debug("TicketLength: "
            + ArrayConverter.bytesToHexString(ArrayConverter.intToBytes(msg.getTicket().getIdentityLength().getValue(),
                HandshakeByteLength.NEWSESSIONTICKET_TICKET_LENGTH)));
    }

    private void writeTicket(NewSessionTicketMessage msg) {
        appendBytes(msg.getTicket().getIdentity().getValue());
        LOGGER.debug("Ticket: " + ArrayConverter.bytesToHexString(msg.getTicket().getIdentity().getValue()));

    }

    private void writeTicketAgeAdd(NewSessionTicketMessage msg) {
        appendBytes(msg.getTicket().getTicketAgeAdd().getValue());
        LOGGER.debug("TicketAgeAdd: " + ArrayConverter.bytesToHexString(msg.getTicket().getTicketAgeAdd().getValue()));
    }

    private void writeTicketNonceLength(NewSessionTicketMessage msg) {
        appendBytes(ArrayConverter.intToBytes(msg.getTicket().getTicketNonceLength().getValue(),
            HandshakeByteLength.TICKET_NONCE_LENGTH));
        LOGGER.debug("TicketNonceLength: " + msg.getTicket().getTicketNonceLength().getValue());
    }

    private void writeTicketNonce(NewSessionTicketMessage msg) {
        appendBytes(msg.getTicket().getTicketNonce().getValue());
        LOGGER.debug("TicketNonce: " + ArrayConverter.bytesToHexString(msg.getTicket().getTicketNonce().getValue()));
    }

    private void writeTicketIdentityLength(NewSessionTicketMessage msg) {
        appendBytes(ArrayConverter.intToBytes(msg.getTicket().getIdentityLength().getValue(),
            ExtensionByteLength.PSK_IDENTITY_LENGTH));
        LOGGER.debug("TicketIdentityLength: " + msg.getTicket().getIdentityLength().getValue());
    }

    private void writeTicketIdentity(NewSessionTicketMessage msg) {
        appendBytes(msg.getTicket().getIdentity().getValue());
        LOGGER.debug("TicketIdentity: " + ArrayConverter.bytesToHexString(msg.getTicket().getIdentity().getValue()));
    }

    private void writeExtensions() {
        if (hasExtensionLengthField()) {
            writeExtensionLength();
            if (hasExtensions()) {
                writeExtensionBytes();
            }
        }
    }
}
