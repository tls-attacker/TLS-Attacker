/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.exceptions.PreparationException;
import de.rub.nds.tlsattacker.tls.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.HelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.RandomHelper;
import de.rub.nds.tlsattacker.util.TimeHelper;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 */
public abstract class HelloMessagePreparator<T extends HelloMessage> extends
        HandshakeMessagePreparator<HandshakeMessage> {

    private final HelloMessage msg;

    public HelloMessagePreparator(TlsContext context, HelloMessage message) {
        super(context, message);
        this.msg = message;
    }

    protected void prepareRandom() {
        byte[] random = new byte[HandshakeByteLength.RANDOM];
        RandomHelper.getRandom().nextBytes(random);
        msg.setRandom(random);
        LOGGER.debug("Random: " + ArrayConverter.bytesToHexString(msg.getRandom().getValue()));
    }

    protected void prepareUnixTime() {
        final long unixTime = TimeHelper.getTime();
        msg.setUnixTime(ArrayConverter.longToUint32Bytes(unixTime));
        LOGGER.debug("UnixTime: " + ArrayConverter.bytesToHexString(msg.getUnixTime().getValue()));
    }

    protected void prepareSessionIDLength() {
        msg.setSessionIdLength(msg.getSessionId().getValue().length);
        LOGGER.debug("SessionIdLength: " + msg.getSessionIdLength().getValue());
    }

    protected void prepareExtensions() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (ExtensionMessage extensionMessage : msg.getExtensions()) {
            ExtensionHandler handler = extensionMessage.getHandler(context);
            handler.getPreparator(extensionMessage).prepare();
            try {
                stream.write(extensionMessage.getExtensionBytes().getValue());
            } catch (IOException ex) {
                throw new PreparationException("Could not write ExtensionBytes to byte[]", ex);
            }
        }
        msg.setExtensionBytes(stream.toByteArray());
        LOGGER.debug("ExtensionBytes: " + ArrayConverter.bytesToHexString(msg.getExtensionBytes().getValue()));
    }

    protected void prepareExtensionLength() {
        msg.setExtensionsLength(msg.getExtensionBytes().getValue().length);
        LOGGER.debug("ExtensionLength: " + msg.getExtensionsLength().getValue());
    }
}
