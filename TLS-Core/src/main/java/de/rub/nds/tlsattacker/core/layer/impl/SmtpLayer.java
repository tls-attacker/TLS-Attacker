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
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.tlsattacker.core.layer.stream.HintedLayerInputStream;
import de.rub.nds.tlsattacker.core.smtp.SmtpCommandType;
import de.rub.nds.tlsattacker.core.smtp.SmtpMessage;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpCommand;
import de.rub.nds.tlsattacker.core.smtp.handler.SmtpMessageHandler;
import de.rub.nds.tlsattacker.core.smtp.parser.command.SmtpCommandParser;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpUnknownReply;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpUnterminatedReply;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A layer that handles the SMTP protocol. It can send and receive SmtpMessages, which represent
 * both commands and replies. Mainly tested for acting as a client right now. Will fallback to
 * SmtpUnknownReply if the type of reply is unclear, but falling back for nonsensical replies is not
 * yet implemented.
 *
 * @see SmtpMessage
 * @see SmtpCommand
 * @see SmtpReply
 */
public class SmtpLayer extends ProtocolLayer<Context, LayerProcessingHint, SmtpMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    private final Context context;
    private final SmtpContext smtpContext;

    public SmtpLayer(Context context) {
        super(ImplementedLayers.SMTP);
        this.context = context;
        this.smtpContext = context.getSmtpContext();
    }

    /**
     * Sends any type of SmtpMessage to lower layers. Because SmtpMessages represent both commands
     * and replies, this method can be used to send both in the same way. It is up to the caller to
     * ensure that the SmtpMessage is of the correct type. There are no LayerProcessingHints for
     * this layer.
     *
     * @return a LayerProcessingResult containing the SmtpMessage that was sent across the different
     *     layers
     * @throws IOException if sending the message fails for any reason
     */
    @Override
    protected LayerProcessingResult sendConfigurationInternal() throws IOException {
        LayerConfiguration<SmtpMessage> configuration = getLayerConfiguration();
        if (configuration != null
                && configuration.getContainerList() != null
                && !configuration.getContainerList().isEmpty()) {
            for (SmtpMessage smtpMsg : getUnprocessedConfiguredContainers()) {
                if (!prepareDataContainer(smtpMsg, context)) {
                    continue;
                }
                SmtpMessageHandler handler = smtpMsg.getHandler(context);
                handler.adjustContext(smtpMsg);
                Serializer<?> serializer = smtpMsg.getSerializer(context);
                byte[] serializedMessage = serializer.serialize();
                //                serializedMessages.write(serializedMessage);
                getLowerLayer().sendData(null, serializedMessage);
                addProducedContainer(smtpMsg);
            }
        }
        return getLayerResult();
    }

    /**
     * Unimplemented method. Would be used to send data from a higher layer via SMTP, which to the
     * best of our knowledge is not a thing.
     *
     * @param hint
     * @param additionalData
     * @return
     * @throws IOException
     */
    @Override
    protected LayerProcessingResult<SmtpMessage> sendDataInternal(
            LayerProcessingHint hint, byte[] additionalData) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     * Receives data by querying the lower layer and processing it. The SmtpLayer can receive both
     * SmtpCommands and SmtpReplies.
     *
     * <p>Implementation-wise this disregards the usual {@link ProtocolLayer#readDataContainer}
     * pattern to be able to parse arbitrary
     *
     * @return a LayerProcessingResult containing the SmtpMessage that was received across the
     *     different layers
     * @see SmtpCommandType
     */
    @Override
    protected LayerProcessingResult<SmtpMessage> receiveDataInternal() {
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
                    SmtpReply smtpReply = smtpContext.getExpectedNextReplyType();
                    if (smtpReply instanceof SmtpUnknownReply) {
                        LOGGER.trace(
                                "Expected reply type unclear, receiving {} instead",
                                smtpReply.getClass().getSimpleName());
                    }
                    readDataContainer(smtpReply, context);
                } else if (context.getChooser().getConnection().getLocalConnectionEndType()
                        == ConnectionEndType.SERVER) {
                    // this shadows the readDataContainer method from the superclass, but we need to
                    // parse the command twice to determine the correct subclass
                    SmtpCommandType smtpCommand = SmtpCommandType.UNKNOWN;
                    ByteArrayOutputStream command = new ByteArrayOutputStream();
                    try {
                        // read from datastream until we hit a space
                        while (dataStream.available() > 0) {
                            char c = (char) dataStream.read();
                            if (c == ' ') {
                                smtpCommand = SmtpCommandType.fromKeyword(command.toString());
                                command.write(c);
                                break;
                            }
                            command.write(c);
                        }

                        SmtpCommand trueCommand = smtpCommand.createCommand();
                        // this will be the actual parsing of the command
                        HintedLayerInputStream smtpCommandStream =
                                new HintedLayerInputStream(null, this);
                        smtpCommandStream.extendStream(command.toByteArray());
                        smtpCommandStream.extendStream(dataStream.readAllBytes());
                        SmtpCommandParser parser =
                                trueCommand.getParser(context, smtpCommandStream);

                        parser.parse(trueCommand);
                        Preparator preparator = trueCommand.getPreparator(context);
                        preparator.prepareAfterParse();
                        Handler handler = trueCommand.getHandler(context);
                        handler.adjustContext(trueCommand);
                        addProducedContainer(trueCommand);
                    } catch (IOException e) {
                        // SmtpCommand will be UNKNOWN, so we can ignore this exception
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
            // SMTP should be a terminal layer, so we should not have any unread bytes unless it is
            // not CRLF terminated

            // previous readDataContainer() call should have consumed all bytes
            setUnreadBytes(new byte[0]);
            // TODO: This deserves a broader class of DataContainer, which is not SMTP-specific
            readDataContainer(new SmtpUnterminatedReply(), context);
            // TODO: Is this the right way to handle this? It feels like this case definitely
            // empties the stream
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
        // SMTP does not work with the current TLSA semantics, as essentially every execution is
        // valid in the sense that the server will always reply with something, that could be a
        // valid reply.
        // e.g. "550 User unknown" would be a valid reply to a HELP command because the status code
        // 550 is overloaded and the message is not standardized.
        return true;
    }
}
