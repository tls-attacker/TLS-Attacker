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
import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.hints.Pop3LayerHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.tlsattacker.core.layer.stream.HintedLayerInputStream;
import de.rub.nds.tlsattacker.core.pop3.Pop3MappingUtil;
import de.rub.nds.tlsattacker.core.pop3.Pop3Message;
import de.rub.nds.tlsattacker.core.pop3.command.Pop3Command;
import de.rub.nds.tlsattacker.core.pop3.command.Pop3UnknownCommand;
import de.rub.nds.tlsattacker.core.pop3.handler.Pop3MessageHandler;
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3CommandParser;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3Reply;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3UnknownReply;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3UnterminatedReply;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A layer that handles the SMTP protocol. It can send and receive SmtpMessages, which represent
 * both commands and replies. Mainly supports acting as a client right now. Currently, it does not
 * parse received commands into the correct subclass, but rather into a generic SmtpReply object.
 * Will fall back to SmtpUnknownReply if the type of reply is unclear, but falling back for
 * nonsensical replies is not yet implemented.
 */
public class Pop3Layer extends ProtocolLayer<Pop3LayerHint, Pop3Message> {
    private static final Logger LOGGER = LogManager.getLogger();

    private final Pop3Context context;

    public Pop3Layer(Pop3Context pop3Context) {
        super(ImplementedLayers.POP3);
        this.context = pop3Context;
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
        LayerConfiguration<Pop3Message> configuration = getLayerConfiguration();
        ByteArrayOutputStream serializedMessages = new ByteArrayOutputStream();
        if (configuration != null && configuration.getContainerList() != null) {
            for (Pop3Message pop3Msg : getUnprocessedConfiguredContainers()) {
                if (!prepareDataContainer(pop3Msg, context)) {
                    continue;
                }
                Pop3MessageHandler handler = pop3Msg.getHandler(context);
                handler.adjustContext(pop3Msg);
                Serializer<?> serializer = pop3Msg.getSerializer(context);
                byte[] serializedMessage = serializer.serialize();
                serializedMessages.write(serializedMessage);
                addProducedContainer(pop3Msg);
            }
            getLowerLayer().sendData(null, serializedMessages.toByteArray());
        }
        return getLayerResult();
    }

    @Override
    public LayerProcessingResult sendData(Pop3LayerHint hint, byte[] additionalData)
            throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     * Receives data by querying the lower layer and processing it. The SmtpLayer can receive both
     * SmtpCommands and SmtpReplies. There are several shortcomings at the moment: Because of the
     * command-reply structure, the type of reply is currently inferred from the preceding command.
     * This is not ideal, as it may lead to incorrect parsing if the server sends an unexpected
     * reply. In the future, we want to parse this into an UnknownReply and handle it accordingly.
     *
     * <p>When receiving a command, the SmtpLayer will parse it into a SmtpCommand object and does
     * not parse it into the correct subclass. This is because it's essentially reading the stream
     * to infer the correct Parser and then repeating the stream again to parse it. Will hopefully
     * be implemented in the future.
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
                    Pop3Reply smtpReply = context.getExpectedNextReplyType();
                    if (smtpReply instanceof Pop3UnknownReply) {
                        LOGGER.trace(
                                "Expected reply type unclear, receiving {} instead",
                                smtpReply.getClass().getSimpleName());
                    }
                    readDataContainer(smtpReply, context);
                } else if (context.getContext().getConnection().getLocalConnectionEndType()
                        == ConnectionEndType.SERVER) {
                    // this shadows the readDataContainer method from the superclass, but we need to
                    // parse the command twice to determine the correct subclass
                    Pop3Command pop3Command = new Pop3Command();
                    Pop3CommandParser verbParser = pop3Command.getParser(context, dataStream);
                    try {
                        verbParser.parse(pop3Command);
                    } catch (ParserException e) {
                        // should only happen if the command is not CRLF terminated
                        LOGGER.warn("Could not parse command even generically: ", e);
                        setUnreadBytes(verbParser.getAlreadyParsed());
                        continue;
                    }
                    Pop3Command trueCommand =
                            Pop3MappingUtil.getCommandFromCommandName(pop3Command.getCommandName());
                    // this will be the actual parsing of the command
                    HintedLayerInputStream smtpCommandStream =
                            new HintedLayerInputStream(new Pop3LayerHint(), this);
                    smtpCommandStream.extendStream(verbParser.getAlreadyParsed());
                    Pop3CommandParser parser = trueCommand.getParser(context, smtpCommandStream);
                    try {
                        // TODO: this may raise a ParserException if parameters are missing
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
                            trueCommand = new Pop3UnknownCommand();
                            HintedLayerInputStream unknownCommandStream =
                                    new HintedLayerInputStream(new Pop3LayerHint(), this);
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
        if (getUnreadBytes().length > 0) {
            // POP3 should be a terminal layer, so we should not have any unread bytes unless it is
            // not CRLF terminated

            // previous readDataContainer() call should have consumed all bytes
            setUnreadBytes(new byte[0]);
            // TODO: This deserves a broader class of DataContainer, which is not POP3-specific
            readDataContainer(new Pop3UnterminatedReply(), context);
            // TODO: Is this the right way to handle this? It feels like this case definitely
            // empties the stream
            getLowerLayer().removeDrainedInputStream();
        }
        return getLayerResult();
    }

    @Override
    public void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public Pop3Command getCommandType() {
        return new Pop3Command();
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
