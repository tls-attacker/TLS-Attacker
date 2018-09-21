/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.SupplementalDataMessage;

/**
 * TODO
 */
public class SupplementalDataSerializer extends HandshakeMessageSerializer<SupplementalDataMessage> {
    /**
     * The message that should be serialized
     */
    private final SupplementalDataMessage msg;

    /**
     * Constructor for the SupplementalDataMessageSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            The Version for which this message should be serialized
     */
    public SupplementalDataSerializer(SupplementalDataMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        throw new UnsupportedOperationException("Not Implemented");
    }
}
