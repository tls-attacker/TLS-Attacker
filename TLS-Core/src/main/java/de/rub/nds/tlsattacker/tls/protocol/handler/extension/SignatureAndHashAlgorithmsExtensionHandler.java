/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.ProtocolMessageParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.SignatureAndHashAlgorithmsExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.SignatureAndHashAlgorithmsExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.SignatureAndHashAlgorithmsExtensionSerializer;
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

    public SignatureAndHashAlgorithmsExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    protected void adjustTLSContext(SignatureAndHashAlgorithmsExtensionMessage message) {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    @Override
    public SignatureAndHashAlgorithmsExtensionParser getParser(byte[] message, int pointer) {
        return new SignatureAndHashAlgorithmsExtensionParser(pointer, message);
    }

    @Override
    public SignatureAndHashAlgorithmsExtensionPreparator getPreparator(
            SignatureAndHashAlgorithmsExtensionMessage message) {
        return new SignatureAndHashAlgorithmsExtensionPreparator(context, message);
    }

    @Override
    public SignatureAndHashAlgorithmsExtensionSerializer getSerializer(
            SignatureAndHashAlgorithmsExtensionMessage message) {
        return new SignatureAndHashAlgorithmsExtensionSerializer(message);
    }

}
