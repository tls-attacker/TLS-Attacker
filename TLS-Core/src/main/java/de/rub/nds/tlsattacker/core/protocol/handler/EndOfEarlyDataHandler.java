/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.EndOfEarlyDataMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.EndOfEarlyDataParser;
import de.rub.nds.tlsattacker.core.protocol.parser.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.EndOfEarlyDataPreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.EndOfEarlyDataSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.record.cipher.RecordAEADCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

/**
 * RFC draft-ietf-tls-tls13-21
 *
 * @author Marcel Maehren <marcel.maehren@rub.de>
 */
public class EndOfEarlyDataHandler extends HandshakeMessageHandler<EndOfEarlyDataMessage> {

    public EndOfEarlyDataHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ProtocolMessageParser getParser(byte[] message, int pointer) {
        return new EndOfEarlyDataParser(pointer, message, tlsContext.getLastRecordVersion());
    }

    @Override
    public ProtocolMessagePreparator getPreparator(EndOfEarlyDataMessage message) {
        return new EndOfEarlyDataPreparator(tlsContext.getChooser(), message);
    }

    @Override
    public ProtocolMessageSerializer getSerializer(EndOfEarlyDataMessage message) {
        return new EndOfEarlyDataSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(EndOfEarlyDataMessage message) {
        if(tlsContext.getConnectionEnd().getConnectionEndType() == ConnectionEndType.CLIENT)
        {
            adjustRecordLayer0RTT();
        }
        //recordLayer is being adjusted in RecordDecryptor, to decrypt ClientFinished
    }
    
    private void adjustRecordLayer0RTT()
    {
        LOGGER.debug("Adjusting recordCipher to encrypt EOED properly");
        
        tlsContext.setStoredSequenceNumberDec(((RecordAEADCipher)((TlsRecordLayer)tlsContext.getRecordLayer()).getRecordCipher()).getSequenceNumberDec());
        tlsContext.setUseEarlyTrafficSecret(true);
        
        RecordCipher recordCipher = RecordCipherFactory.getRecordCipher(tlsContext, tlsContext.getEarlyDataCipherSuite());
        tlsContext.getRecordLayer().setRecordCipher(recordCipher);
        tlsContext.getRecordLayer().updateDecryptionCipher();
        tlsContext.getRecordLayer().updateEncryptionCipher();
        
        ((RecordAEADCipher)recordCipher).setSequenceNumberEnc(1); //Sequence number has to be 1, as ClientHello was already encrypted using ETSecret
        tlsContext.setEncryptedEndOfEarlyData(true);
    }

}
