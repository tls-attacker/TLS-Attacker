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
import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class SignatureAndHashAlgorithmsExtensionHandler extends
        ExtensionHandler<SignatureAndHashAlgorithmsExtensionMessage> {

    private static SignatureAndHashAlgorithmsExtensionHandler instance;

    public static final int SIGNATURE_AND_HASH_ALGORITHMS_LENGTH = 2;

    public SignatureAndHashAlgorithmsExtensionHandler() {

    }

    /**
     * @param extension
     */
    @Override
    public void prepareExtension(TlsContext context) {
        SignatureAndHashAlgorithmsExtensionMessage extension = (SignatureAndHashAlgorithmsExtensionMessage) extensionMessage;
        if (extension == null) {
            extension = new SignatureAndHashAlgorithmsExtensionMessage(context.getConfig());
        }
        byte[] algorithms = new byte[0];
        for (SignatureAndHashAlgorithm algorithm : context.getConfig().getSupportedSignatureAndHashAlgorithms()) {
            algorithms = ArrayConverter.concatenate(algorithms, algorithm.getByteValue());
        }

        extension.setExtensionType(ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS.getValue());
        extension.setSignatureAndHashAlgorithms(algorithms);
        extension.setSignatureAndHashAlgorithmsLength(algorithms != null ? algorithms.length : 0);
        extension.setExtensionLength(extension.getSignatureAndHashAlgorithmsLength().getValue()
                + ExtensionByteLength.EXTENSIONS);

        byte[] extensionBytes = ArrayConverter.concatenate(extension.getExtensionType().getValue(), ArrayConverter
                .intToBytes(extension.getExtensionLength().getValue(), ExtensionByteLength.EXTENSIONS), ArrayConverter
                .intToBytes(extension.getSignatureAndHashAlgorithmsLength().getValue(),
                        SIGNATURE_AND_HASH_ALGORITHMS_LENGTH), extension.getSignatureAndHashAlgorithms().getValue());

        extension.setExtensionBytes(extensionBytes);
    }

    /**
     * This method parses the signature and hash algorithms extension out of a
     * byte message.
     *
     * @param message
     *            is the message as byte array, which contains the extension
     * @param pointer
     *            points to the first byte of the signature and hash algorithms
     *            extension
     * @return points to the first byte after the SignatureAndHashAlgorithms
     *         extension
     */
    @Override
    public int parseExtension(byte[] message, int pointer) {
        SignatureAndHashAlgorithmsExtensionMessage extension;
        if (extensionMessage == null) {
            extension = new SignatureAndHashAlgorithmsExtensionMessage();
        } else {
            extension = (SignatureAndHashAlgorithmsExtensionMessage) extensionMessage;
        }
        // check if correct extension is passed
        if (message[pointer] != (byte) 0 && message[pointer + 1] != (byte) 13) {
            throw new IllegalArgumentException(
                    "Extension isn't a SignatureAndHashAlgorithms Extension. First Bytes should be '0' and '13'");
        }
        // set extension type
        extension.setExtensionType(ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS.getValue());
        int newPointer = pointer + ExtensionByteLength.TYPE;

        // set extension and signature and hash algorithm extension length
        extension.setExtensionLength(ArrayConverter.bytesToInt(new byte[] { message[newPointer],
                message[newPointer + 1] }));
        newPointer += ExtensionByteLength.EXTENSIONS;

        extension.setSignatureAndHashAlgorithmsLength(ArrayConverter.bytesToInt(new byte[] { message[newPointer],
                message[newPointer + 1] }));
        newPointer += SIGNATURE_AND_HASH_ALGORITHMS_LENGTH;

        // create the SignatureAndHashAlgorithmsConfig (List) and the byte
        // values of them
        int pairingsCount = extension.getSignatureAndHashAlgorithmsLength().getValue() / 2;
        ArrayList<SignatureAndHashAlgorithm> signatureAndHashConfig = new ArrayList<>();
        ByteArrayOutputStream signatureAndHashBytes = new ByteArrayOutputStream();

        for (int i = newPointer; i <= newPointer + pairingsCount; i += 2) {
            signatureAndHashConfig.add(new SignatureAndHashAlgorithm(new byte[] { message[i], message[i + 1] }));
            signatureAndHashBytes.write(message, i, 2);
        }
        extension.setSignatureAndHashAlgorithms(signatureAndHashBytes.toByteArray());
        // the extension bytes are exactly the same, than in the message. Thus
        // we copy them.
        newPointer += extension.getSignatureAndHashAlgorithmsLength().getValue();
        extension.setExtensionBytes(Arrays.copyOfRange(message, pointer, newPointer));
        extensionMessage = extension;
        return newPointer;
    }

}
