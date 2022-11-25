/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.message.AckMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AckPreperator extends ProtocolMessagePreparator<AckMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsContext tlsContext;
    private final AckMessage message;

    public AckPreperator(Chooser chooser, AckMessage message, TlsContext tlsContext) {
        super(chooser, message);
        this.message = message;
        this.tlsContext = tlsContext;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        LOGGER.debug("Preparing AckMessage");
        prepareRecordNumbers();
        prepareRecordLength();
    }

    private void prepareRecordLength() {
        message.setRecordNumberLength(message.getRecordNumbers().getValue().length);
        LOGGER.debug("RecordNumber Length: " + message.getRecordNumberLength());
    }

    private void prepareRecordNumbers() {
        message.setRecordNumbers(createRecordNumberArray());
        LOGGER.debug(
                "RecordNumbers: "
                        + ArrayConverter.bytesToHexString(message.getRecordNumbers().getValue()));
    }

    private byte[] createRecordNumberArray() {
        /*List<BigInteger[]> recordNumbers = tlsContext.getAcknowledgedRecords();
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        try {
            for (BigInteger[] recordNumber : recordNumbers) {
                if (recordNumber.length != 2) {
                    throw new IllegalStateException(
                            "Record number must have exactly 2 elements, bus has "
                                    + recordNumber.length);
                }
                BigInteger epoch = recordNumber[0];
                BigInteger seqNum = recordNumber[1];
                stream.write(ArrayConverter.longToUint64Bytes(epoch.longValue()));
                stream.write(ArrayConverter.longToUint64Bytes(seqNum.longValue()));
            }
        } catch (IOException e) {
            LOGGER.warn("Could not write Record Number in ACK message: ", e);
        }
        return stream.toByteArray();*/

        List<byte[]> recordNumbers = tlsContext.getAcknowledgedRecords();
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        try {
            for (byte[] recordNumber : recordNumbers) {
                stream.write(recordNumber);
            }
        } catch (IOException e) {
            LOGGER.warn("Could not write Record Number in ACK message: ", e);
        }

        // clear acknowledged records
        tlsContext.getAcknowledgedRecords().clear();
        return stream.toByteArray();
    }
}
