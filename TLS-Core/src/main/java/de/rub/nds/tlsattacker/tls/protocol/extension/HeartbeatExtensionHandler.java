/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class HeartbeatExtensionHandler extends ExtensionHandler<HeartbeatExtensionMessage> {

    private static HeartbeatExtensionHandler instance;

    public HeartbeatExtensionHandler() {

    }

    @Override
    public void prepareExtension(TlsContext context) {
        byte[] heartbeatMode = { context.getConfig().getHeartbeatMode().getValue() };
        HeartbeatExtensionMessage extension = (HeartbeatExtensionMessage) extensionMessage;
        extension.setExtensionType(ExtensionType.HEARTBEAT.getValue());
        extension.setHeartbeatMode(heartbeatMode);

        extension.setExtensionLength(extension.getHeartbeatMode().getValue().length);

        byte[] pfExtension = ArrayConverter.concatenate(extension.getExtensionType().getValue(),
                ArrayConverter.intToBytes(extension.getExtensionLength().getValue(), ExtensionByteLength.EXTENSIONS),
                extension.getHeartbeatMode().getValue());

        extension.setExtensionBytes(pfExtension);
    }

    @Override
    public int parseExtension(byte[] message, int pointer) {
        if (extensionMessage == null) {
            extensionMessage = new HeartbeatExtensionMessage();
        }
        HeartbeatExtensionMessage hem = (HeartbeatExtensionMessage) extensionMessage;
        int nextPointer = pointer + ExtensionByteLength.TYPE;
        byte[] extensionType = Arrays.copyOfRange(message, pointer, nextPointer);
        hem.setExtensionType(extensionType);

        pointer = nextPointer;
        nextPointer = pointer + ExtensionByteLength.EXTENSIONS;
        int extensionLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, pointer, nextPointer));
        hem.setExtensionLength(extensionLength);

        pointer = nextPointer;
        byte[] mode = { message[pointer] };
        hem.setHeartbeatMode(mode);
        //TODO set heartbeat mode in tlsContext
        byte[] result = ArrayConverter.concatenate(hem.getExtensionType().getValue(), ArrayConverter.intToBytes(hem
                .getExtensionLength().getValue(), ExtensionByteLength.EXTENSIONS), hem.getHeartbeatMode().getValue());
        hem.setExtensionBytes(result);

        return pointer + 1;
    }

}
