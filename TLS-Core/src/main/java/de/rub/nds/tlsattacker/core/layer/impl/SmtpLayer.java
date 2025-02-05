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
import de.rub.nds.tlsattacker.core.exceptions.TimeoutException;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.hints.SmtpLayerHint;
import de.rub.nds.tlsattacker.core.smtp.SmtpMessage;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpCommand;
import de.rub.nds.tlsattacker.core.smtp.handler.SmtpMessageHandler;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpUnknownReply;
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
     * SmtpCommands and SmtpReplies. There are several shortcomings at the moment: Because of the
     * command-reply structure, the type of reply is currently inferred from the preceding command.
     * This is not ideal, as it may lead to incorrect parsing if the server sends an unexpected
     * reply. In the future, we want to parse this into an UnknownReply and handle it accordingly.
     *
     * <p>When receiving a command, the SmtpLayer will parse it into a SmtpCommand object and does
     * not parse it into the correct subclass. This is because it essentially reading the stream to
     * infer the correct Parser and then repeating the stream again to parse it. Will hopefully be
     * implemented in the future.
     *
     * @return a LayerProcessingResult containing the SmtpMessage that was received across the
     *     different layers
     */
    @Override
    public LayerProcessingResult receiveData() {
        try {
            do {
                if (context.getContext().getConnection().getLocalConnectionEndType()
                        == ConnectionEndType.CLIENT) {
                    SmtpReply smtpReply = context.getExpectedNextReplyType();
                    if (smtpReply != null) {
                        LOGGER.trace(
                                "Expecting reply of type: {}",
                                smtpReply.getClass().getSimpleName());
                    } else {
                        smtpReply = new SmtpUnknownReply();
                        LOGGER.trace(
                                "Expected reply type unclear, receiving {} instead",
                                smtpReply.getClass().getSimpleName());
                    }
                    readDataContainer(smtpReply, context);
                } else if (context.getContext().getConnection().getLocalConnectionEndType()
                        == ConnectionEndType.SERVER) {
                    SmtpCommand smtpCommand = new SmtpCommand();
                    readDataContainer(smtpCommand, context);
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
        return getLayerResult();
    }

    @Override
    public void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public SmtpCommand getCommandType() {
        return new SmtpCommand();
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

    //    @Override
    //    public boolean shouldContinueProcessing() {
    //        return super.shouldContinueProcessing() && this.getUnreadBytes() != null &&
    // this.getUnreadBytes().length > 0;
    //    }
}
