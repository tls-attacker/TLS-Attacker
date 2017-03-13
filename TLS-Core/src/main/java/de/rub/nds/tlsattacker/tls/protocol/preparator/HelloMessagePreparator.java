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
import de.rub.nds.tlsattacker.tls.protocol.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.HelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.RandomHelper;
import de.rub.nds.tlsattacker.util.TimeHelper;
import java.io.ByteArrayOutputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class HelloMessagePreparator<T extends HelloMessage> extends
        HandshakeMessagePreparator<HandshakeMessage> {

    private static final Logger LOGGER = LogManager.getLogger("PREPARATOR");
    
    private final HelloMessage message;

    public HelloMessagePreparator(TlsContext context, HelloMessage message) {
        super(context, message);
        this.message = message;
    }

    protected void prepareRandom() {
        byte[] random = new byte[HandshakeByteLength.RANDOM];
        RandomHelper.getRandom().nextBytes(random);
        message.setRandom(random);
    }

    protected void prepareUnixTime() {
        final long unixTime = TimeHelper.getTime();
        message.setUnixTime(ArrayConverter.longToUint32Bytes(unixTime));
    }

    protected void prepareSessionIDLength() {
        message.setSessionIdLength(message.getSessionId().getValue().length);
    }

    protected void prepareExtensions() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (ExtensionMessage extensionMessage : message.getExtensions()) {
            // TODO
        }
        message.setExtensionBytes(stream.toByteArray());
    }

    protected void prepareExtensionLength() {
        message.setExtensionsLength(message.getExtensionBytes().getValue().length);
    }
}
