/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.EndOfEarlyDataMessage;

/**
 * RFC draft-ietf-tls-tls13-21
 */
public class EndOfEarlyDataSerializer extends HandshakeMessageSerializer<EndOfEarlyDataMessage> {

    public EndOfEarlyDataSerializer(EndOfEarlyDataMessage message, ProtocolVersion version) {
        super(message, version);
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        return getAlreadySerialized(); // empty message
    }

}
