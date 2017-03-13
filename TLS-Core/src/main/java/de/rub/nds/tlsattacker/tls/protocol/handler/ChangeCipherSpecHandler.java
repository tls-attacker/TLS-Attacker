/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler;

import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.crypto.TlsRecordBlockCipher;
import de.rub.nds.tlsattacker.tls.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.tls.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.ChangeCipherSpecParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.Parser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.ChangeCipherSpecPreparator;
import de.rub.nds.tlsattacker.tls.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.CertificateMessageSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.ChangeCipherSpecSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class ChangeCipherSpecHandler extends ProtocolMessageHandler<ChangeCipherSpecMessage> {

    private static final Logger LOGGER = LogManager.getLogger("HANDLER");
    
    public ChangeCipherSpecHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ChangeCipherSpecParser getParser(byte[] message, int pointer) {
        return new ChangeCipherSpecParser(pointer, message, tlsContext.getLastRecordVersion());
    }

    @Override
    public Preparator getPreparator(ChangeCipherSpecMessage message) {
        return new ChangeCipherSpecPreparator(tlsContext, message);
    }

    @Override
    public Serializer getSerializer(ChangeCipherSpecMessage message) {
        return new ChangeCipherSpecSerializer(message, tlsContext.getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(ChangeCipherSpecMessage message) {
        if (tlsContext.getTalkingConnectionEnd() == tlsContext.getConfig().getMyConnectionEnd()) {
            setRecordCipher();
            tlsContext.getRecordHandler().setEncryptSending(true);
        } else {
            setRecordCipher();
            tlsContext.getRecordHandler().setDecryptReceiving(true);
        }
    }

    private void setRecordCipher() {
        try {
            TlsRecordBlockCipher tlsRecordBlockCipher = new TlsRecordBlockCipher(tlsContext);
            tlsContext.getRecordHandler().setRecordCipher(tlsRecordBlockCipher);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidAlgorithmParameterException ex) {
            throw new AdjustmentException("Could not initialize an EncryptionAlgorithm from "
                    + tlsContext.getSelectedCipherSuite().name() + ".", ex);
        }
    }
}
