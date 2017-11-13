/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ApplicationMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ApplicationMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ApplicationMessageSerializer;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Marcel Maehren <marcel.maehren@rub.de>
 */
public class ApplicationHandler extends ProtocolMessageHandler<ApplicationMessage> {

    public ApplicationHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ApplicationMessageParser getParser(byte[] message, int pointer) {
        return new ApplicationMessageParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public ApplicationMessagePreparator getPreparator(ApplicationMessage message) {
        return new ApplicationMessagePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public ApplicationMessageSerializer getSerializer(ApplicationMessage message) {
        return new ApplicationMessageSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(ApplicationMessage message) {
        if(tlsContext.isUseEarlyTrafficSecret())
        {
            adjustRecordLayer0RTT();
        }
        tlsContext.setLastHandledApplicationMessageData(message.getData().getValue());
        String readableAppData = ArrayConverter.bytesToHexString(tlsContext.getLastHandledApplicationMessageData());
        if (tlsContext.getTalkingConnectionEndType() == tlsContext.getChooser().getMyConnectionPeer()) {
            LOGGER.debug("Received Data:" + readableAppData);
        } else {
            LOGGER.debug("Send Data:" + readableAppData);
        }
    }
    
    private void adjustRecordLayer0RTT()
    {
        LOGGER.debug("Setting up RecordLayer, to allow for EarlyData encryption");
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS13); //Needed to avoid "Only supported for TLS 1.3" exception
            
        RecordCipher recordCipher = RecordCipherFactory.getRecordCipher(tlsContext, tlsContext.getEarlyDataCipherSuite());
        tlsContext.getRecordLayer().setRecordCipher(recordCipher);
        tlsContext.getRecordLayer().updateDecryptionCipher();
        tlsContext.getRecordLayer().updateEncryptionCipher();
        tlsContext.setEncryptActive(true);
    }

}
