/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.protocol.exception.EndOfStreamException;
import de.rub.nds.protocol.exception.TimeoutException;
import de.rub.nds.tlsattacker.core.ftp.FtpCommandType;
import de.rub.nds.tlsattacker.core.ftp.FtpMessage;
import de.rub.nds.tlsattacker.core.ftp.command.FtpCommand;
import de.rub.nds.tlsattacker.core.ftp.handler.FtpMessageHandler;
import de.rub.nds.tlsattacker.core.ftp.parser.command.FtpCommandParser;
import de.rub.nds.tlsattacker.core.ftp.reply.FtpReply;
import de.rub.nds.tlsattacker.core.ftp.reply.FtpUnknownReply;
import de.rub.nds.tlsattacker.core.ftp.reply.FtpUnterminatedReply;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.FtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.tlsattacker.core.layer.stream.HintedLayerInputStream;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A layer that handles the FTP protocol control connection for the RFC 4217 STARTTLS upgrade. It
 * can send and receive FtpMessages, which represent both commands and replies. When acting as a
 * client, the type of reply is inferred from the preceding command.
 */
public class FtpLayer extends ProtocolLayer<Context, LayerProcessingHint, FtpMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    private final Context context;
    private final FtpContext ftpContext;

    public FtpLayer(Context context) {
        super(ImplementedLayers.FTP);
        this.context = context;
        this.ftpContext = context.getFtpContext();
    }

    /**
     * Sends any type of FtpMessage to lower layers. Because FtpMessages represent both commands and
     * replies, this method can be used to send both in the same way. It is up to the caller to
     * ensure that the FtpMessage is of the correct type. There are no LayerProcessingHints for this
     * layer.
     *
     * @return a LayerProcessingResult containing the FtpMessage that was sent across the different
     *     layers
     * @throws IOException if sending the message fails for any reason
     */
    @Override
    protected LayerProcessingResult<FtpMessage> sendConfigurationInternal() throws IOException {
        LayerConfiguration<FtpMessage> configuration = getLayerConfiguration();
        if (configuration != null && configuration.getContainerList() != null) {
            for (FtpMessage ftpMsg : getUnprocessedConfiguredContainers()) {
                if (!prepareDataContainer(ftpMsg, context)) {
                    continue;
                }
                FtpMessageHandler handler = ftpMsg.getHandler(context);
                handler.adjustContext(ftpMsg);
                Serializer<?> serializer = ftpMsg.getSerializer(context);
                byte[] serializedMessage = serializer.serialize();
                addProducedContainer(ftpMsg);
                getLowerLayer().sendData(null, serializedMessage);
            }
        }
        return getLayerResult();
    }

    @Override
    protected LayerProcessingResult sendDataInternal(
            LayerProcessingHint hint, byte[] additionalData) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     * Receives data by querying the lower layer and processing it. The FtpLayer can receive both
     * FtpCommands and FtpReplies. When acting as a client, the reply type is inferred from the
     * preceding command. When acting as a server, the layer reads the command keyword up to the
     * first space, then parses the remainder.
     *
     * @return a LayerProcessingResult containing the FtpMessage that was received across the
     *     different layers
     */
    @Override
    protected LayerProcessingResult<FtpMessage> receiveDataInternal() {
        try {
            HintedInputStream dataStream;
            do {
                try {
                    dataStream = getLowerLayer().getDataStream();
                } catch (IOException e) {
                    // the lower layer does not give us any data so we can simply return here
                    LOGGER.warn("The lower layer did not produce a data stream: ", e);
                    return getLayerResult();
                }
                if (context.getChooser().getConnection().getLocalConnectionEndType()
                        == ConnectionEndType.CLIENT) {
                    FtpReply ftpReply = ftpContext.getExpectedNextReplyType();
                    if (ftpReply instanceof FtpUnknownReply) {
                        LOGGER.trace(
                                "Expected reply type unclear, receiving {} instead",
                                ftpReply.getClass().getSimpleName());
                    }
                    readDataContainer(ftpReply, context);
                } else if (context.getChooser().getConnection().getLocalConnectionEndType()
                        == ConnectionEndType.SERVER) {
                    FtpCommandType ftpCommand = FtpCommandType.UNKNOWN;
                    ByteArrayOutputStream command = new ByteArrayOutputStream();
                    try {
                        // read from datastream until we hit a space
                        while (dataStream.available() > 0) {
                            char c = (char) dataStream.read();
                            if (c == ' ') {
                                ftpCommand =
                                        FtpCommandType.fromKeyword(
                                                command.toString(StandardCharsets.US_ASCII));
                                command.write(c);
                                break;
                            }
                            command.write(c);
                        }

                        FtpCommand trueCommand = ftpCommand.createCommand();
                        HintedLayerInputStream ftpCommandStream =
                                new HintedLayerInputStream(null, this);
                        ftpCommandStream.extendStream(command.toByteArray());
                        ftpCommandStream.extendStream(dataStream.readAllBytes());
                        FtpCommandParser parser = trueCommand.getParser(context, ftpCommandStream);

                        parser.parse(trueCommand);
                        Preparator preparator = trueCommand.getPreparator(context);
                        preparator.prepareAfterParse();
                        Handler handler = trueCommand.getHandler(context);
                        handler.adjustContext(trueCommand);
                        addProducedContainer(trueCommand);
                    } catch (IOException ex) {
                        // FtpCommand will be UNKNOWN, so we can ignore this exception
                    }
                }
            } while (shouldContinueProcessing());
        } catch (TimeoutException e) {
            LOGGER.debug(e);
        } catch (EndOfStreamException ex) {
            if (getLayerConfiguration() != null
                    && getLayerConfiguration().getContainerList() != null
                    && !getLayerConfiguration().getContainerList().isEmpty()) {
                LOGGER.debug("Reached end of stream, cannot parse more messages", ex);
            } else {
                LOGGER.debug("No messages required for layer.");
            }
        }
        if (getUnreadBytes().length > 0) {
            // FTP should be a terminal layer, so we should not have any unread bytes unless the
            // reply is not CRLF terminated

            // previous readDataContainer() call should have consumed all bytes
            setUnreadBytes(new byte[0]);
            readDataContainer(new FtpUnterminatedReply(), context);
            getLowerLayer().removeDrainedInputStream();
        }
        return getLayerResult();
    }

    @Override
    protected void receiveMoreDataForHintInternal(LayerProcessingHint hint) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean executedAsPlanned() {
        // FTP does not work with the current TLSA semantics, as essentially every execution is
        // valid in the sense that the server will always reply with something that could be a valid
        // reply.
        return true;
    }
}
