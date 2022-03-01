/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.SupplementalDataMessage;

/**
 * TODO
 */
public class SupplementalDataSerializer extends HandshakeMessageSerializer<SupplementalDataMessage> {

    /**
     * Constructor for the SupplementalDataMessageSerializer
     *
     * @param message
     *                Message that should be serialized
     */
    public SupplementalDataSerializer(SupplementalDataMessage message) {
        super(message);
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        throw new UnsupportedOperationException("Not Implemented");
    }
}
