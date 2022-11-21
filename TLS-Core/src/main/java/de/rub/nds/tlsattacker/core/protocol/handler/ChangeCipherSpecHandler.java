/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ChangeCipherSpecParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ChangeCipherSpecPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ChangeCipherSpecSerializer;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChangeCipherSpecHandler extends TlsMessageHandler<ChangeCipherSpecMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChangeCipherSpecHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ChangeCipherSpecParser getParser(byte[] message, int pointer) {
        return new ChangeCipherSpecParser(pointer, message, tlsContext.getChooser().getSelectedProtocolVersion(),
            tlsContext.getConfig());
    }

    @Override
    public ChangeCipherSpecPreparator getPreparator(ChangeCipherSpecMessage message) {
        return new ChangeCipherSpecPreparator(tlsContext.getChooser(), message);
    }

    @Override
    public ChangeCipherSpecSerializer getSerializer(ChangeCipherSpecMessage message) {
        return new ChangeCipherSpecSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(ChangeCipherSpecMessage message) {
        if (tlsContext.getTalkingConnectionEndType() != tlsContext.getChooser().getConnectionEndType()
            && tlsContext.getChooser().getSelectedProtocolVersion() != ProtocolVersion.TLS13) {
            LOGGER.debug("Adjusting decrypting cipher for " + tlsContext.getTalkingConnectionEndType());
            tlsContext.getRecordLayer().updateDecryptionCipher(getRecordCipher());
            tlsContext.getRecordLayer().updateDecompressor();
        }
    }

    @Override
    public void adjustTlsContextAfterSerialize(ChangeCipherSpecMessage message) {
        if (!tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
            LOGGER.debug("Adjusting encrypting cipher for " + tlsContext.getTalkingConnectionEndType());
            tlsContext.getRecordLayer().updateEncryptionCipher(getRecordCipher());
            tlsContext.getRecordLayer().updateCompressor();
        }
    }

    private RecordCipher getRecordCipher() {
        try {
            KeySet keySet = KeySetGenerator.generateKeySet(tlsContext,
                tlsContext.getChooser().getSelectedProtocolVersion(), Tls13KeySetType.NONE);
            return RecordCipherFactory.getRecordCipher(tlsContext, keySet);
        } catch (NoSuchAlgorithmException | CryptoException ex) {
            throw new UnsupportedOperationException("The specified Algorithm is not supported", ex);
        }
    }
}
