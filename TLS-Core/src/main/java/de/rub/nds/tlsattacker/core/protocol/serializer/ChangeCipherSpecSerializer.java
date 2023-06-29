/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChangeCipherSpecSerializer extends ProtocolMessageSerializer<ChangeCipherSpecMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ChangeCipherSpecMessage msg;

    /**
     * Constructor for the ChangerCipherSpecSerializer
     *
     * @param message Message that should be serialized
     */
    public ChangeCipherSpecSerializer(ChangeCipherSpecMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    protected byte[] serializeBytes() {
        LOGGER.debug("Serializing ChangeCipherSepcMessage");
        writeCcsProtocolType(msg);
        return getAlreadySerialized();
    }

    /** Writes the CcsProtocolType of the ChangeCipherSpecMessage into the final byte[] */
    private void writeCcsProtocolType(ChangeCipherSpecMessage msg) {
        appendBytes(msg.getCcsProtocolType().getValue());
        LOGGER.debug("CcsProtocolType: {}", msg.getCcsProtocolType().getValue());
    }
}
