/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import static de.rub.nds.tlsattacker.core.protocol.serializer.Serializer.LOGGER;

/**
 * 
 * @author Timon Wern <timon.wern@rub.de>
 */
public class NewSessionTicketMessageSerializer extends HandshakeMessageSerializer<NewSessionTicketMessage> {
    private final NewSessionTicketMessage msg;

    /**
     * Constructor for the NewSessionTicketMessageSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public NewSessionTicketMessageSerializer(NewSessionTicketMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing NewSessionTicketMessage");
        writeLifetimeHint(msg);
        writeTicketLength(msg);
        writeTicket(msg);
        return getAlreadySerialized();
    }

    private void writeLifetimeHint(NewSessionTicketMessage msg) {
        appendBytes(ArrayConverter.longToBytes(msg.getTicketLifetimeHint().getValue(), HandshakeByteLength.NEWSESSIONTICKET_LIFETIMEHINT_LENGTH));
        LOGGER.debug("LifetimeHint: "
                + ArrayConverter.bytesToHexString(ArrayConverter.longToBytes(msg.getTicketLifetimeHint().getValue(), HandshakeByteLength.NEWSESSIONTICKET_LIFETIMEHINT_LENGTH)));
    }

    private void writeTicketLength(NewSessionTicketMessage msg) {
        appendBytes(ArrayConverter.intToBytes(msg.getTicketLength().getValue(), HandshakeByteLength.NEWSESSIONTICKET_TICKET_LENGTH));
        LOGGER.debug("TicketLength: "
                + ArrayConverter.bytesToHexString(ArrayConverter.intToBytes(msg.getTicketLength().getValue(), HandshakeByteLength.NEWSESSIONTICKET_TICKET_LENGTH)));
    }

    private void writeTicket(NewSessionTicketMessage msg) {
        appendBytes(msg.getTicket().getKeyName().getValue());
        LOGGER.debug("Keyname: " + ArrayConverter.bytesToHexString(msg.getTicket().getKeyName().getValue()));
        appendBytes(msg.getTicket().getIV().getValue());
        LOGGER.debug("IV: " + ArrayConverter.bytesToHexString(msg.getTicket().getIV().getValue()));
        appendBytes(msg.getTicket().getEncryptedState().getValue());
        LOGGER.debug("EncryptedState: "
                + ArrayConverter.bytesToHexString(msg.getTicket().getEncryptedState().getValue()));
        appendBytes(msg.getTicket().getMAC().getValue());
        LOGGER.debug("MAC: " + ArrayConverter.bytesToHexString(msg.getTicket().getMAC().getValue()));
    }
}
