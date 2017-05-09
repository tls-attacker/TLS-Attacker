/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.AlertHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ApplicationHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ChangeCipherSpecHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.HeartbeatHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.UnknownMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.factory.HandlerFactory;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.util.HashMap;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public enum ProtocolMessageType {
    UNKNOWN((byte) 99),
    CHANGE_CIPHER_SPEC((byte) 20),
    ALERT((byte) 21),
    HANDSHAKE((byte) 22),
    APPLICATION_DATA((byte) 23),
    HEARTBEAT((byte) 24);

    private byte value;

    private static final Map<Byte, ProtocolMessageType> MAP;

    private ProtocolMessageType(byte value) {
        this.value = value;
    }

    static {
        MAP = new HashMap<>();
        for (ProtocolMessageType cm : ProtocolMessageType.values()) {
            MAP.put(cm.value, cm);
        }
    }

    public static ProtocolMessageType getContentType(byte value) {
        return MAP.get(value);
    }

    public byte getValue() {
        return value;
    }

    public byte[] getArrayValue() {
        return new byte[] { value };
    }
}
