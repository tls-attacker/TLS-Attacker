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
public class MaxFragmentLengthExtensionHandler extends ExtensionHandler<MaxFragmentLengthExtensionMessage> {

    /**
     * Max fragment length
     */
    public static final int MAX_FRAGMENT_LENGTH = 1;

    public MaxFragmentLengthExtensionHandler() {
    }

    @Override
    public void prepareExtension(TlsContext context) {
        byte[] maxFragmentLength = { context.getConfig().getMaxFragmentLength().getValue() };
        MaxFragmentLengthExtensionMessage extension = (MaxFragmentLengthExtensionMessage) extensionMessage;
        if (extension == null) {
            extension = new MaxFragmentLengthExtensionMessage(context.getConfig());
        }
        extension.setExtensionType(ExtensionType.MAX_FRAGMENT_LENGTH.getValue());
        extension.setMaxFragmentLength(maxFragmentLength);
        extension.setExtensionLength(extension.getMaxFragmentLength().getValue().length);
        byte[] result = ArrayConverter.concatenate(extension.getExtensionType().getValue(),
                ArrayConverter.intToBytes(extension.getExtensionLength().getValue(), ExtensionByteLength.EXTENSIONS),
                extension.getMaxFragmentLength().getValue());

        extension.setExtensionBytes(result);
    }

    @Override
    public int parseExtension(byte[] message, int pointer) {
        if (extensionMessage == null) {
            extensionMessage = new MaxFragmentLengthExtensionMessage();
        }
        MaxFragmentLengthExtensionMessage mflExtension = (MaxFragmentLengthExtensionMessage) extensionMessage;
        int nextPointer = pointer + ExtensionByteLength.TYPE;
        byte[] extensionType = Arrays.copyOfRange(message, pointer, nextPointer);
        mflExtension.setExtensionType(extensionType);

        pointer = nextPointer;
        nextPointer = pointer + ExtensionByteLength.EXTENSIONS;
        int extensionLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, pointer, nextPointer));
        mflExtension.setExtensionLength(extensionLength);

        pointer = nextPointer;
        byte[] fragmentLength = { message[pointer] };
        mflExtension.setMaxFragmentLength(fragmentLength);
        // TODO set in tlsContext
        byte[] result = ArrayConverter
                .concatenate(mflExtension.getExtensionType().getValue(), ArrayConverter.intToBytes(mflExtension
                        .getExtensionLength().getValue(), ExtensionByteLength.EXTENSIONS), mflExtension
                        .getMaxFragmentLength().getValue());
        mflExtension.setExtensionBytes(result);

        return pointer + 1;
    }

}
