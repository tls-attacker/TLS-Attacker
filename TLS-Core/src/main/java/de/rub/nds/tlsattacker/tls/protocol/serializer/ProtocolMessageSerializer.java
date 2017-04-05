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
import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 */
public abstract class ProtocolMessageSerializer<T extends ProtocolMessage> extends Serializer<T> {

    private static final Logger LOGGER = LogManager.getLogger("SERIALIZER");

    protected ProtocolVersion version;

    /**
     * Constructor for the ProtocolMessageSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public ProtocolMessageSerializer(T message, ProtocolVersion version) {
        this.version = version;
    }

    @Override
    protected final byte[] serializeBytes() {
        return serializeProtocolMessageContent();
    }

    public abstract byte[] serializeProtocolMessageContent();
}
