/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.EndOfStreamException;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.hints.RecordLayerHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.tlsattacker.core.layer.stream.HintedLayerInputStream;
import de.rub.nds.tlsattacker.core.protocol.parser.cert.CleanRecordByteSeperator;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.compressor.RecordCompressor;
import de.rub.nds.tlsattacker.core.record.compressor.RecordDecompressor;
import de.rub.nds.tlsattacker.core.record.crypto.Decryptor;
import de.rub.nds.tlsattacker.core.record.crypto.Encryptor;
import de.rub.nds.tlsattacker.core.record.crypto.RecordDecryptor;
import de.rub.nds.tlsattacker.core.record.crypto.RecordEncryptor;
import de.rub.nds.tlsattacker.core.record.parser.RecordParser;
import de.rub.nds.tlsattacker.core.record.preparator.RecordPreparator;
import de.rub.nds.tlsattacker.core.record.serializer.RecordSerializer;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The record layer encrypts and encapsulates payload or handshake messages into TLS records. It
 * sends the records using the lower layer.
 */
public class RecordLayer extends ProtocolLayer<RecordLayerHint, Record> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsContext context;

    private final Decryptor decryptor;
    private final Encryptor encryptor;

    private final RecordCompressor compressor;
    private final RecordDecompressor decompressor;

    private int writeEpoch = 0;
    private int readEpoch = 0;

    public RecordLayer(TlsContext context) {
        super(ImplementedLayers.RECORD);
        this.context = context;
        encryptor = new RecordEncryptor(RecordCipherFactory.getNullCipher(context), context);
        decryptor = new RecordDecryptor(RecordCipherFactory.getNullCipher(context), context);
        compressor = new RecordCompressor(context);
        decompressor = new RecordDecompressor(context);
    }

    /**
     * Sends the records given in the LayerConfiguration using the lower layer.
     *
     * @return LayerProcessingResult A result object containing information about the sent records
     * @throws IOException When the data cannot be sent
     */
    @Override
    public LayerProcessingResult sendConfiguration() throws IOException {
        LayerConfiguration<Record> configuration = getLayerConfiguration();
        if (configuration != null && configuration.getContainerList() != null) {
            for (Record record : configuration.getContainerList()) {
                if (containerAlreadyUsedByHigherLayer(record) || skipEmptyRecords(record)) {
                    continue;
                }
                ProtocolMessageType contentType = record.getContentMessageType();
                if (contentType == null) {
                    contentType = ProtocolMessageType.UNKNOWN;
                    LOGGER.warn(
                            "Sending record without a LayerProcessing hint. Using \"UNKNOWN\" as the type");
                }
                if (encryptor.getRecordCipher(writeEpoch).getState().getVersion().isDTLS()
                        && record.getEpoch() == null) {
                    record.setEpoch(writeEpoch);
                }
                if (record.getCleanProtocolMessageBytes() == null) {
                    record.setCleanProtocolMessageBytes(new byte[0]);
                }
                RecordPreparator preparator =
                        record.getRecordPreparator(context, encryptor, compressor, contentType);
                preparator.prepare();
                preparator.afterPrepare();
                RecordSerializer serializer = record.getRecordSerializer();
                byte[] serializedMessage = serializer.serialize();
                record.setCompleteRecordBytes(serializedMessage);
                getLowerLayer().sendData(null, serializedMessage);
                addProducedContainer(record);
            }
        }
        return getLayerResult();
    }

    private boolean skipEmptyRecords(Record record) {
        return !context.getConfig().isUseAllProvidedRecords()
                && record.getCompleteRecordBytes() != null
                && record.getCompleteRecordBytes().getValue().length == 0;
    }

    /**
     * Sends data from an upper layer using the lower layer. Puts the given bytes into records and
     * sends those.
     *
     * @param hint Contains information about the message to be sent, including the message type.
     * @param data The data to send
     * @return LayerProcessingResult A result object containing information about the sent records
     * @throws IOException When the data cannot be sent
     */
    @Override
    public LayerProcessingResult<Record> sendData(RecordLayerHint hint, byte[] data)
            throws IOException {
        ProtocolMessageType type = ProtocolMessageType.UNKNOWN;
        if (hint != null) {
            type = hint.getType();
        } else {
            LOGGER.warn(
                    "Sending record without a LayerProcessing hint. Using \"UNKNOWN\" as the type");
        }

        // Generate records
        CleanRecordByteSeperator separator =
                new CleanRecordByteSeperator(
                        context.getChooser().getOutboundMaxRecordDataSize(),
                        new ByteArrayInputStream(data),
                        context.getConfig().isCreateRecordsDynamically());
        List<Record> records = new LinkedList<>();

        List<Record> givenRecords = getLayerConfiguration().getContainerList();

        // if we are given records we should assign messages to them
        if (getLayerConfiguration().getContainerList() != null && givenRecords.size() > 0) {
            if (context.getConfig().getPreserveMessageRecordRelation()) {
                // put this message into the first container of this layer
                // also remove the container from the ones we want to send later
                records.add(givenRecords.remove(0));
            } else {
                // assign as many records as we need for the message
                int dataToBeSent = data.length;
                while (givenRecords.size() > 0 && dataToBeSent > 0) {
                    Record nextRecord = givenRecords.remove(0);
                    records.add(nextRecord);
                    int recordData =
                            (nextRecord.getMaxRecordLengthConfig() != null
                                    ? nextRecord.getMaxRecordLengthConfig()
                                    : context.getChooser().getOutboundMaxRecordDataSize());
                    dataToBeSent -= recordData;
                }
            }
        }

        separator.parse(records);
        if (separator.getBytesLeft() > 0) {
            LOGGER.warn(
                    "Unsent bytes for message "
                            + type
                            + ". Not enough records specified and disabled dynamic record creation in config.");
        }
        ByteArrayOutputStream stream = new ByteArrayOutputStream();

        // prepare, serialize, and send records
        for (Record record : records) {
            ProtocolMessageType contentType = record.getContentMessageType();
            if (contentType == null) {
                contentType = type;
            }
            if (encryptor.getRecordCipher(writeEpoch).getState().getVersion().isDTLS()) {
                record.setEpoch(writeEpoch);
            }
            RecordPreparator preparator =
                    record.getRecordPreparator(context, encryptor, compressor, contentType);
            preparator.prepare();
            preparator.afterPrepare();
            try {
                byte[] recordBytes = record.getRecordSerializer().serialize();
                record.setCompleteRecordBytes(recordBytes);
                stream.write(record.getCompleteRecordBytes().getValue());
            } catch (IOException ex) {
                throw new PreparationException(
                        "Could not write Record bytes to ByteArrayStream", ex);
            }
            addProducedContainer(record);
        }
        getLowerLayer().sendData(null, stream.toByteArray());
        return new LayerProcessingResult<>(records, getLayerType(), true);
    }

    /**
     * Receive more data for the upper layer using the lower layer.
     *
     * @param desiredHint This hint from the calling layer specifies which data its wants to read.
     * @throws IOException When no data can be read
     */
    @Override
    public void receiveMoreDataForHint(LayerProcessingHint desiredHint) throws IOException {
        InputStream dataStream = getLowerLayer().getDataStream();
        RecordParser parser =
                new RecordParser(dataStream, getDecryptorCipher().getState().getVersion(), context);
        try {
            Record record = new Record();
            parser.parse(record);
            // TODO it would be good to have a record handler here
            ProtocolVersion protocolVersion =
                    ProtocolVersion.getProtocolVersion(record.getProtocolVersion().getValue());
            context.setLastRecordVersion(protocolVersion);
            decryptor.decrypt(record);
            decompressor.decompress(record);
            addProducedContainer(record);
            RecordLayerHint currentHint;
            // extract the type of the message we just read
            if (context.getChooser().getSelectedProtocolVersion().isDTLS()) {
                currentHint =
                        new RecordLayerHint(
                                record.getContentMessageType(),
                                record.getEpoch().getValue(),
                                record.getSequenceNumber().getValue().intValue());
            } else {
                currentHint = new RecordLayerHint(record.getContentMessageType());
            }
            // only set the currentInputStream when we received the expected message
            if (desiredHint == null || currentHint.equals(desiredHint)) {
                if (currentInputStream == null) {
                    // only set new input stream if necessary, extend current stream otherwise
                    currentInputStream = new HintedLayerInputStream(currentHint, this);
                } else {
                    currentInputStream.setHint(currentHint);
                }
                currentInputStream.extendStream(record.getCleanProtocolMessageBytes().getValue());
            } else {
                if (nextInputStream == null) {
                    // only set new input stream if necessary, extend current stream otherwise
                    nextInputStream = new HintedLayerInputStream(currentHint, this);
                } else {
                    nextInputStream.setHint(currentHint);
                }
                nextInputStream.extendStream(record.getCleanProtocolMessageBytes().getValue());
            }
        } catch (ParserException e) {
            setUnreadBytes(parser.getAlreadyParsed());
            LOGGER.warn(
                    "Could not parse Record as a Record. Passing data to upper layer as unknown data",
                    e);
            HintedInputStream tempStream =
                    new HintedLayerInputStream(
                            new RecordLayerHint(ProtocolMessageType.UNKNOWN), this);
            tempStream.extendStream(dataStream.readAllBytes());
            if (currentInputStream == null) {
                currentInputStream = tempStream;
            } else {
                nextInputStream = tempStream;
            }
        } catch (EndOfStreamException ex) {
            setUnreadBytes(parser.getAlreadyParsed());
            LOGGER.debug("Reached end of stream, cannot parse more records", ex);
            throw ex;
        }
    }

    public RecordCipher getEncryptorCipher() {
        return encryptor.getRecordMostRecentCipher();
    }

    public RecordCipher getDecryptorCipher() {
        return decryptor.getRecordMostRecentCipher();
    }

    public void updateCompressor() {
        compressor.setMethod(context.getChooser().getSelectedCompressionMethod());
    }

    public void updateDecompressor() {
        decompressor.setMethod(context.getChooser().getSelectedCompressionMethod());
    }

    public void updateEncryptionCipher(RecordCipher encryptionCipher) {
        LOGGER.debug(
                "Activating new EncryptionCipher ({})",
                encryptionCipher.getClass().getSimpleName());
        encryptor.addNewRecordCipher(encryptionCipher);
        writeEpoch++;
    }

    public void updateDecryptionCipher(RecordCipher decryptionCipher) {
        LOGGER.debug(
                "Activating new DecryptionCipher ({})",
                decryptionCipher.getClass().getSimpleName());
        decryptor.addNewRecordCipher(decryptionCipher);
        readEpoch++;
    }

    /**
     * Re-encrypts already send record bytes in DTLS retransmission.
     *
     * @param records Records to send
     * @return byte array of the encrypted records.
     */
    public byte[] reencrypt(List<Record> records) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (Record record : records) {
            RecordPreparator preparator =
                    record.getRecordPreparator(
                            this.context,
                            getEncryptor(),
                            getCompressor(),
                            record.getContentMessageType());
            preparator.encrypt();
            try {
                byte[] recordBytes = record.getRecordSerializer().serialize();
                record.setCompleteRecordBytes(recordBytes);
                stream.write(record.getCompleteRecordBytes().getValue());
            } catch (IOException ex) {
                throw new PreparationException(
                        "Could not write Record bytes to ByteArrayStream", ex);
            }
        }
        return stream.toByteArray();
    }

    public void resetEncryptor() {
        encryptor.removeAllCiphers();
    }

    public void resetDecryptor() {
        decryptor.removeAllCiphers();
    }

    public Encryptor getEncryptor() {
        return encryptor;
    }

    public Decryptor getDecryptor() {
        return decryptor;
    }

    public RecordCompressor getCompressor() {
        return compressor;
    }

    public RecordDecompressor getDecompressor() {
        return decompressor;
    }

    public void increaseWriteEpoch() {
        writeEpoch++;
    }

    public int getWriteEpoch() {
        return writeEpoch;
    }

    public void setWriteEpoch(int writeEpoch) {
        this.writeEpoch = writeEpoch;
    }

    public void increaseReadEpoch() {
        readEpoch++;
    }

    public int getReadEpoch() {
        return readEpoch;
    }

    public void setReadEpoch(int readEpoch) {
        this.readEpoch = readEpoch;
    }

    @Override
    public LayerProcessingResult receiveData() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
