/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.SupplementalDataMessage;

/** TODO */
public class SupplementalDataSerializer
        extends HandshakeMessageSerializer<SupplementalDataMessage> {

    /**
     * Constructor for the SupplementalDataMessageSerializer
     *
     * @param message Message that should be serialized
     */
    public SupplementalDataSerializer(SupplementalDataMessage message) {
        super(message);
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        throw new UnsupportedOperationException("Not Implemented");
    }
}
