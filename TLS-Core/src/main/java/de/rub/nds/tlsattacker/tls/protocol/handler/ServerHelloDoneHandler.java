/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.exceptions.InvalidMessageTypeException;
import de.rub.nds.tlsattacker.tls.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.Parser;
import de.rub.nds.tlsattacker.tls.protocol.parser.ServerHelloDoneParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.tls.protocol.preparator.ServerHelloDonePreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.ServerHelloDoneSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.modifiablevariable.util.ArrayConverter;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class ServerHelloDoneHandler extends HandshakeMessageHandler<ServerHelloDoneMessage> {

    public ServerHelloDoneHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ServerHelloDoneParser getParser(byte[] message, int pointer) {
        return new ServerHelloDoneParser(pointer, message, tlsContext.getLastRecordVersion());
    }

    @Override
    public ServerHelloDonePreparator getPreparator(ServerHelloDoneMessage message) {
        return new ServerHelloDonePreparator(tlsContext, message);
    }

    @Override
    public ServerHelloDoneSerializer getSerializer(ServerHelloDoneMessage message) {
        return new ServerHelloDoneSerializer(message, tlsContext.getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(ServerHelloDoneMessage message) {
        // nothing to adjust here
    }
}
