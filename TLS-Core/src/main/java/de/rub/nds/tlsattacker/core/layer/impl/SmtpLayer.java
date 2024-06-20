package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.tlsattacker.core.exceptions.TimeoutException;
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.http.HttpMessageHandler;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.LayerType;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.hints.SmtpLayerHint;
import de.rub.nds.tlsattacker.core.smtp.SmtpMessage;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpCommand;
import de.rub.nds.tlsattacker.core.smtp.handler.SmtpMessageHandler;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;

public class SmtpLayer extends ProtocolLayer<SmtpLayerHint, SmtpMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    private final SmtpContext context;

    public SmtpLayer(SmtpContext smtpContext) {
        super(ImplementedLayers.SMTP);
        this.context = smtpContext;
    }

    @Override
    public LayerProcessingResult sendConfiguration() throws IOException {
        LayerConfiguration<SmtpMessage> configuration = getLayerConfiguration();
        if (configuration != null && configuration.getContainerList() != null) {
            for (SmtpMessage smtpMsg : getUnprocessedConfiguredContainers()) {
                if (!prepareDataContainer(smtpMsg, context)) {
                    continue;
                }
                SmtpMessageHandler<?> handler = smtpMsg.getHandler(context);
                //handler.adjustContext((HttpMessage) httpMsg);
                Serializer<?> serializer = smtpMsg.getSerializer(context);
                byte[] serializedMessage = serializer.serialize();
                getLowerLayer().sendData(null, serializedMessage);
                addProducedContainer(smtpMsg);
            }
        }
        return getLayerResult();
    }

    @Override
    public LayerProcessingResult sendData(SmtpLayerHint hint, byte[] additionalData) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public LayerProcessingResult receiveData() {
        try {
            do {
                if(context.getContext().getConnection().getLocalConnectionEndType() == ConnectionEndType.CLIENT) {
                    SmtpCommand smtpCommand = new SmtpCommand();
                    readDataContainer(smtpCommand, context);
                } else if (context.getContext().getConnection().getLocalConnectionEndType() == ConnectionEndType.SERVER) {
                    //TODO: What to do when the client receives an unknown reply?
                    SmtpReply smtpReply = context.getExpectedNextReplyType();
                    readDataContainer(smtpReply, context);
                }
            } while (shouldContinueProcessing());
        } catch (TimeoutException e) {
            LOGGER.debug(e);
        }
        return getLayerResult();
    }

    @Override
    public void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public SmtpCommand getCommandType(){
        return new SmtpCommand();
    }
}
