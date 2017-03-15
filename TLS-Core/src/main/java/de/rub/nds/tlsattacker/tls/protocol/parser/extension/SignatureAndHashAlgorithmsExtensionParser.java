/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.tls.protocol.extension.SignatureAndHashAlgorithmsExtensionMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class SignatureAndHashAlgorithmsExtensionParser extends ExtensionParser<SignatureAndHashAlgorithmsExtensionMessage>{

    public SignatureAndHashAlgorithmsExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public SignatureAndHashAlgorithmsExtensionMessage parse() {
        SignatureAndHashAlgorithmsExtensionMessage msg = new SignatureAndHashAlgorithmsExtensionMessage();
        parseExtensionType(msg);
        parseExtensionLength(msg);
        msg.setSignatureAndHashAlgorithmsLength(parseIntField(ExtensionByteLength.SIGNATURE_AND_HASH_ALGORITHMS_LENGTH));
        msg.setSignatureAndHashAlgorithms(parseByteArrayField(msg.getSignatureAndHashAlgorithmsLength().getValue()));
        return msg;
    }
    
}
