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
import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.tlsattacker.core.layer.stream.HintedLayerInputStream;
import de.rub.nds.tlsattacker.core.pop3.Pop3CommandType;
import de.rub.nds.tlsattacker.core.pop3.Pop3Message;
import de.rub.nds.tlsattacker.core.pop3.command.Pop3Command;
import de.rub.nds.tlsattacker.core.pop3.handler.Pop3MessageHandler;
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3CommandParser;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3Reply;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3UnknownReply;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3UnterminatedReply;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A layer that handles the POP3 protocol. It can send and receive Pop3Messages, which represent
 * both commands and replies. Mainly supports acting as a client right now. Currently, it does not
 * parse received commands into the correct subclass, but rather into a generic Pop3Reply object.
 * Will fall back to Pop3UnknownReply if the type of reply is unclear, but falling back for
 * nonsensical replies is not yet implemented.
 */
public class Pop3Layer extends ProtocolLayer<Context, LayerProcessingHint, Pop3Message> {
    private static final Logger LOGGER = LogManager.getLogger();

    private final Context context;
    private final Pop3Context pop3Context;

    public Pop3Layer(Context context) {
        super(ImplementedLayers.POP3);
        this.context = context;
        this.pop3Context = context.getPop3Context();
    }

    /**
     * Sends any type of Pop3Message to lower layers. Because Pop3Messages represent both commands
     * and replies, this method can be used to send both in the same way. It is up to the caller to
     * ensure that the Pop3Message is of the correct type. There are no LayerProcessingHints for
     * this layer.
     *
     * @return a LayerProcessingResult containing the Pop3Message that was sent across the different
     *     layers
     * @throws IOException if sending the message fails for any reason
     */
    @Override
    public LayerProcessingResult<Pop3Message> sendConfigurationInternal() throws IOException {
        LayerConfiguration<Pop3Message> configuration = getLayerConfiguration();
        if (configuration != null && configuration.getContainerList() != null) {
            for (Pop3Message pop3Msg : getUnprocessedConfiguredContainers()) {
                if (!prepareDataContainer(pop3Msg, context)) {
                    continue;
                }
                Pop3MessageHandler handler = pop3Msg.getHandler(context);
                handler.adjustContext(pop3Msg);
                Serializer<?> serializer = pop3Msg.getSerializer(context);
                byte[] serializedMessage = serializer.serialize();
                addProducedContainer(pop3Msg);
                getLowerLayer().sendData(null, serializedMessage);
            }
        }
        return getLayerResult();
    }

    @Override
    public LayerProcessingResult sendDataInternal(LayerProcessingHint hint, byte[] additionalData)
            throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     * Receives data by querying the lower layer and processing it. The Pop3Layer can receive both
     * Pop3Commands and Pop3Replies. There are several shortcomings at the moment: Because of the
     * command-reply structure, the type of reply is currently inferred from the preceding command.
     * This is not ideal, as it may lead to incorrect parsing if the server sends an unexpected
     * reply. In the future, we want to parse this into an UnknownReply and handle it accordingly.
     *
     * <p>When receiving a command, the Pop3Layer will parse it into a Pop3Command object and does
     * not parse it into the correct subclass. This is because it's essentially reading the stream
     * to infer the correct Parser and then repeating the stream again to parse it. Will hopefully
     * be implemented in the future.
     *
     * @return a LayerProcessingResult containing the Pop3Message that was received across the
     *     different layers
     */
    @Override
    public LayerProcessingResult<Pop3Message> receiveDataInternal() {
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
                    Pop3Reply pop3Reply = pop3Context.getExpectedNextReplyType();
                    if (pop3Reply instanceof Pop3UnknownReply) {
                        LOGGER.trace(
                                "Expected reply type unclear, receiving {} instead",
                                pop3Reply.getClass().getSimpleName());
                    }
                    readDataContainer(pop3Reply, context);
                } else if (context.getChooser().getConnection().getLocalConnectionEndType()
                        == ConnectionEndType.SERVER) {
                    Pop3CommandType pop3Command = Pop3CommandType.UNKNOWN;
                    ByteArrayOutputStream command = new ByteArrayOutputStream();
                    try {
                        // read from datastream until we hit a space
                        while (dataStream.available() > 0) {
                            char c = (char) dataStream.read();
                            if (c == ' ') {
                                pop3Command = Pop3CommandType.fromKeyword(command.toString());
                                command.write(c);
                                break;
                            }
                            command.write(c);
                        }

                        Pop3Command trueCommand = pop3Command.createCommand();
                        // this will be the actual parsing of the command
                        HintedLayerInputStream pop3CommandStream =
                                new HintedLayerInputStream(null, this);
                        pop3CommandStream.extendStream(command.toByteArray());
                        pop3CommandStream.extendStream(dataStream.readAllBytes());
                        Pop3CommandParser parser =
                                trueCommand.getParser(context, pop3CommandStream);

                        parser.parse(trueCommand);
                        Preparator preparator = trueCommand.getPreparator(context);
                        preparator.prepareAfterParse();
                        Handler handler = trueCommand.getHandler(context);
                        handler.adjustContext(trueCommand);
                        addProducedContainer(trueCommand);
                    } catch (IOException ex) {
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
    public void receiveMoreDataForHintInternal(LayerProcessingHint hint) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean executedAsPlanned() {
        // TODO: Properly check status codes etc here
        // POP3 does not work with the current TLSA semantics, as essentially every execution is
        // valid in the sense that the server will always reply with something, that could be a
        // valid reply.
        return true;
    }
}
