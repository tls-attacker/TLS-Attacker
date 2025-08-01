/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.HelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.util.TimeHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @param <T> The HelloMessage that should be prepared
 */
public abstract class HelloMessagePreparator<T extends HelloMessage>
        extends HandshakeMessagePreparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final T msg;

    public HelloMessagePreparator(Chooser chooser, T message) {
        super(chooser, message);
        this.msg = message;
    }

    protected void prepareRandom() {
        byte[] random;
        if (msg instanceof ServerHelloMessage && ((ServerHelloMessage) msg).isHelloRetryRequest()) {
            random = ServerHelloMessage.getHelloRetryRequestRandom();
        } else if (chooser.getConfig().isUseFreshRandom()) {
            if (chooser.getHighestProtocolVersion().is13()) {
                random = new byte[HandshakeByteLength.RANDOM];
                chooser.getContext().getTlsContext().getRandom().nextBytes(random);
                chooser.getContext().getTlsContext().setServerRandom(random);
            } else {
                random = new byte[HandshakeByteLength.RANDOM - HandshakeByteLength.UNIX_TIME];
                chooser.getContext().getTlsContext().getRandom().nextBytes(random);
                msg.setUnixTime(DataConverter.longToUint32Bytes(TimeHelper.getTime()));
                random = DataConverter.concatenate(msg.getUnixTime().getValue(), random);
                chooser.getContext().getTlsContext().setServerRandom(random);
            }
        } else {
            if (chooser.getTalkingConnectionEnd() == ConnectionEndType.CLIENT) {
                random = chooser.getClientRandom();
            } else {
                random = chooser.getServerRandom();
            }
        }
        msg.setRandom(random);
        LOGGER.debug("Random: {}", msg.getRandom().getValue());
    }

    protected void prepareSessionIDLength() {
        msg.setSessionIdLength(msg.getSessionId().getValue().length);
        LOGGER.debug("SessionIdLength: {}", msg.getSessionIdLength().getValue());
    }
}
