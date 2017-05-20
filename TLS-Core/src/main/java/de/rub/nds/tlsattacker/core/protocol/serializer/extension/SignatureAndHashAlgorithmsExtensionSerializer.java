/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class SignatureAndHashAlgorithmsExtensionSerializer extends
        ExtensionSerializer<SignatureAndHashAlgorithmsExtensionMessage> {

    private final SignatureAndHashAlgorithmsExtensionMessage message;

    public SignatureAndHashAlgorithmsExtensionSerializer(SignatureAndHashAlgorithmsExtensionMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        appendInt(message.getSignatureAndHashAlgorithmsLength().getValue(),
                ExtensionByteLength.SIGNATURE_AND_HASH_ALGORITHMS_LENGTH);
        appendBytes(message.getSignatureAndHashAlgorithms().getValue());
        return getAlreadySerialized();
    }
}
