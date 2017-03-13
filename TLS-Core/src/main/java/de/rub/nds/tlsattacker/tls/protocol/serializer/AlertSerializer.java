/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer;

import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.AlertMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class AlertSerializer extends ProtocolMessageSerializer<AlertMessage> {

    private final AlertMessage message;

    public AlertSerializer(AlertMessage message, ProtocolVersion version) {
        super(message, version);
        this.message = message;
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        appendByte(message.getLevel().getValue());
        appendByte(message.getDescription().getValue());
        return getAlreadySerialized();
    }

}
