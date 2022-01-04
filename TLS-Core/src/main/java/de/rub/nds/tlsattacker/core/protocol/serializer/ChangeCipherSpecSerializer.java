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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChangeCipherSpecSerializer extends TlsMessageSerializer<ChangeCipherSpecMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ChangeCipherSpecMessage msg;

    /**
     * Constructor for the ChangerCipherSpecSerializer
     *
     * @param message
     *                Message that should be serialized
     * @param version
     *                Version of the Protocol
     */
    public ChangeCipherSpecSerializer(ChangeCipherSpecMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        LOGGER.debug("Serializing ChangeCipherSepcMessage");
        writeCcsProtocolType(msg);
        return getAlreadySerialized();
    }

    /**
     * Writes the CcsProtocolType of the ChangeCipherSpecMessage into the final byte[]
     */
    private void writeCcsProtocolType(ChangeCipherSpecMessage msg) {
        appendBytes(msg.getCcsProtocolType().getValue());
        LOGGER.debug("CcsProtocolType: " + ArrayConverter.bytesToHexString(msg.getCcsProtocolType().getValue()));
    }

}
