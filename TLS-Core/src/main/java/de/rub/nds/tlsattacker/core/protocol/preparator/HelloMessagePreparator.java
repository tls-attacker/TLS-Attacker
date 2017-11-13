/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.util.TimeHelper;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 */
public abstract class HelloMessagePreparator<T extends HelloMessage> extends
        HandshakeMessagePreparator<HandshakeMessage> {

    private final HelloMessage msg;

    public HelloMessagePreparator(Chooser chooser, HelloMessage message) { 
        super(chooser, message);
        this.msg = message;
    }

    protected void prepareRandom(ProtocolVersion version) {
        byte[] random;
        if (chooser.getConfig().isUseRandomUnixTime()) {
            random = new byte[HandshakeByteLength.RANDOM - HandshakeByteLength.UNIX_TIME];
            chooser.getContext().getRandom().nextBytes(random);
            msg.setUnixTime(ArrayConverter.longToUint32Bytes(TimeHelper.getTime()));
            random = ArrayConverter.concatenate(msg.getUnixTime().getValue(), random);
            msg.setRandom(random);
        } else {
            random = new byte[HandshakeByteLength.RANDOM];
            chooser.getContext().getRandom().nextBytes(random);
            msg.setRandom(random);
        }

        LOGGER.debug("Random: " + ArrayConverter.bytesToHexString(msg.getRandom().getValue()));
    }

    protected void prepareSessionIDLength() {
        msg.setSessionIdLength(msg.getSessionId().getValue().length);
        LOGGER.debug("SessionIdLength: " + msg.getSessionIdLength().getValue());
    }

}
