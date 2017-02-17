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
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class UnknownExtensionHandler extends ExtensionHandler<UnknownExtensionMessage> {

    public UnknownExtensionHandler() {
    }

    @Override
    public void prepareExtension(TlsContext context) {
        UnknownExtensionMessage extension = (UnknownExtensionMessage) extensionMessage;
        extension.setExtensionType(extension.getTypeConfig());
        extension.setExtensionLength(extension.getLengthConfig());
        extension.setExtensionBytes(extension.getExtensionBytes());
    }

    @Override
    public int parseExtension(byte[] message, int pointer) {
        if (extensionMessage == null) {
            extensionMessage = new UnknownExtensionMessage();
        }
        UnknownExtensionMessage unknownExtension = (UnknownExtensionMessage) extensionMessage;

        int nextPointer = pointer + ExtensionByteLength.TYPE;
        byte[] extensionType = Arrays.copyOfRange(message, pointer, nextPointer);
        unknownExtension.setExtensionType(extensionType);
        pointer = nextPointer;
        nextPointer = pointer + ExtensionByteLength.EXTENSIONS;
        int extensionLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, pointer, nextPointer));
        unknownExtension.setExtensionLength(extensionLength);

        pointer = nextPointer;
        byte[] extensionData = Arrays.copyOfRange(message, pointer, pointer + extensionLength);
        pointer = pointer + extensionLength;
        unknownExtension.setExtensionData(extensionData);
        byte[] result = ArrayConverter.concatenate(unknownExtension.getExtensionType().getValue(), ArrayConverter
                .intToBytes(unknownExtension.getExtensionLength().getValue(), ExtensionByteLength.EXTENSIONS),
                unknownExtension.getExtensionData().getValue());
        unknownExtension.setExtensionBytes(result);

        return pointer;
    }

}
