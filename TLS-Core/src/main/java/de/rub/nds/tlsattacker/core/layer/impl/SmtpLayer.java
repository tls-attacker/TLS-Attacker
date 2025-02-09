/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.tlsattacker.core.exceptions.EndOfStreamException;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.exceptions.TimeoutException;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.hints.SmtpLayerHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.tlsattacker.core.layer.stream.HintedLayerInputStream;
import de.rub.nds.tlsattacker.core.smtp.SmtpMessage;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpCommand;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpUnknownCommand;
import de.rub.nds.tlsattacker.core.smtp.handler.SmtpMessageHandler;
import de.rub.nds.tlsattacker.core.smtp.parser.SmtpMessageParser;
import de.rub.nds.tlsattacker.core.smtp.parser.command.SmtpCommandParser;
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpReplyParser;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpUnknownReply;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpUnterminatedReply;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A layer that handles the SMTP protocol. It can send and receive SmtpMessages, which represent
 * both commands and replies. Mainly supports acting as a client right now. Currently it does not
 * parse received commands into the correct subclass, but rather into a generic SmtpReply object.
 * Will fallback to SmtpUnknownReply if the type of reply is unclear, but falling back for
 * nonsensical replies is not yet implemented.
 */
public class SmtpLayer extends ProtocolLayer<SmtpLayerHint, SmtpMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    private final SmtpContext context;

    public static final int MAX_COMMAND_LENGTH = 512;
    public static final int MAX_REPLY_LENGTH = 1024*64; // recommendation for the minimum maximum length according 4.5.3.1.7.  Message Content


    public SmtpLayer(SmtpContext smtpContext) {
        super(ImplementedLayers.SMTP);
        this.context = smtpContext;
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
    public LayerProcessingResult sendConfiguration() throws IOException {
        LayerConfiguration<SmtpMessage> configuration = getLayerConfiguration();
        if (configuration != null && configuration.getContainerList() != null) {
            for (SmtpMessage smtpMsg : getUnprocessedConfiguredContainers()) {
                if (!prepareDataContainer(smtpMsg, context)) {
                    continue;
                }
                SmtpMessageHandler handler = smtpMsg.getHandler(context);
                handler.adjustContext(smtpMsg);
                Serializer<?> serializer = smtpMsg.getSerializer(context);
                byte[] serializedMessage = serializer.serialize();
                getLowerLayer().sendData(null, serializedMessage);
                addProducedContainer(smtpMsg);
            }
        }
        return getLayerResult();
    }

    @Override
    public LayerProcessingResult sendData(SmtpLayerHint hint, byte[] additionalData)
            throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     * Receives data by querying the lower layer and processing it. The SmtpLayer can receive both
     * SmtpCommands and SmtpReplies. There are several shortcomings at the moment:
     *
     * @return a LayerProcessingResult containing the SmtpMessage that was received across the
     *     different layers
     */
    @Override
    public LayerProcessingResult receiveData() {
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
                if (context.getContext().getConnection().getLocalConnectionEndType()
                        == ConnectionEndType.CLIENT) {
                    SmtpReply smtpReply = context.getExpectedNextReplyType();
                    if(smtpReply instanceof SmtpUnknownReply) {
                        LOGGER.trace(
                                "Expected reply type unclear, receiving {} instead",
                                smtpReply.getClass().getSimpleName());
                    }
                    readDataContainer(smtpReply, context);
                } else if (context.getContext().getConnection().getLocalConnectionEndType()
                        == ConnectionEndType.SERVER) {
                    // this shadows the readDataContainer method from the superclass, but we need to parse the command twice to determine the correct subclass
                    SmtpCommand smtpCommand = new SmtpCommand();
                    SmtpCommandParser verbParser = smtpCommand.getParser(context, dataStream);
                    try {
                        verbParser.parse(smtpCommand);
                    } catch (ParserException e) {
                        // should only happen if the command is not CRLF terminated
                        LOGGER.warn("Could not parse command even generically: ", e);
                        setUnreadBytes(verbParser.getAlreadyParsed());
                        continue;
                    }
                    SmtpCommand trueCommand = SmtpContext.getCommandTypeFromVerb(smtpCommand.getVerb());
                    // this will be the actual parsing of the command
                    HintedLayerInputStream smtpCommandStream = new HintedLayerInputStream(new SmtpLayerHint(), this);
                    smtpCommandStream.extendStream(verbParser.getAlreadyParsed());
                    SmtpCommandParser parser = trueCommand.getParser(context, smtpCommandStream);
                    try {
                        //TODO: this may raise a ParserException if parameters are missing
                        parser.parse(trueCommand);
                        Preparator preparator = trueCommand.getPreparator(context);
                        preparator.prepareAfterParse();
                        Handler handler = trueCommand.getHandler(context);
                        handler.adjustContext(trueCommand);
                        addProducedContainer(trueCommand);
                    } catch (RuntimeException ex) {
                        // only if the ParserException is caused by the command-specific parsing
                        // we fall back to the parsing as an unknown
                        try {
                            trueCommand = new SmtpUnknownCommand();
                            HintedLayerInputStream unknownCommandStream = new HintedLayerInputStream(new SmtpLayerHint(), this);
                            unknownCommandStream.extendStream(verbParser.getAlreadyParsed());
                            parser = trueCommand.getParser(context, unknownCommandStream);
                            parser.parse(trueCommand);
                            Preparator preparator = trueCommand.getPreparator(context);
                            preparator.prepareAfterParse();
                            Handler handler = trueCommand.getHandler(context);
                            handler.adjustContext(trueCommand);
                            addProducedContainer(trueCommand);
                        } catch (ParserException e) {
                            LOGGER.warn("Could not parse command: ", e);
                            setUnreadBytes(verbParser.getAlreadyParsed());
                        }
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
        if(getUnreadBytes().length > 0) {
            // SMTP should be a terminal layer, so we should not have any unread bytes unless it is not CRLF terminated

            //previous readDataContainer() call should have consumed all bytes
            setUnreadBytes(new byte[0]);
            //TODO: This deserves a broader class of DataContainer, which is not SMTP-specific
            readDataContainer(new SmtpUnterminatedReply(), context);
            //TODO: Is this the right way to handle this? It feels like this case definitely empties the stream
            getLowerLayer().removeDrainedInputStream();
        }
        return getLayerResult();
    }

    @Override
    public void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean executedAsPlanned() {
        // TODO: Properly check status codes etc here
        // SMTP does not work with the current TLSA semantics, as essentially every execution is
        // valid in the sense that the server will always reply with something, that could be a
        // valid reply.
        // e.g. "550 User unknown" would be a valid reply to a HELP command because the status code
        // 550 is overloaded and the message is not standardized.
        return true;
    }
}
