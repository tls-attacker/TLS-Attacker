/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerStackProcessingResult;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.printer.LogPrinter;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.container.ActionHelperUtil;
import jakarta.xml.bind.annotation.XmlElement;
import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class CommonForwardAction extends TlsAction
        implements ReceivingAction, SendingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlElement(name = "from")
    protected String receiveFromAlias = null;

    @XmlElement(name = "to")
    protected String forwardToAlias = null;

    @XmlElement(name = "receiveResult")
    private LayerStackProcessingResult layerStackReceiveResult;

    @XmlElement(name = "sendResult")
    private LayerStackProcessingResult layerStackSendResult;

    public CommonForwardAction() {}

    public CommonForwardAction(String receiveFromAlias, String forwardToAlias) {
        this.receiveFromAlias = receiveFromAlias;
        this.forwardToAlias = forwardToAlias;
    }

    public void setReceiveFromAlias(String receiveFromAlias) {
        this.receiveFromAlias = receiveFromAlias;
    }

    public void setForwardToAlias(String forwardToAlias) {
        this.forwardToAlias = forwardToAlias;
    }

    public String getReceiveFromAlias() {
        return receiveFromAlias;
    }

    public String getForwardToAlias() {
        return forwardToAlias;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        assertAliasesSetProperly();

        TlsContext receiveFromContext = state.getTlsContext(receiveFromAlias);
        TlsContext forwardToContext = state.getTlsContext(forwardToAlias);

        List<LayerConfiguration<?>> layerConfigurationList =
                createReceiveConfiguration(receiveFromContext);
        if (layerConfigurationList == null) {
            LOGGER.info("Not receiving messages");
        } else {
            LOGGER.info(
                    "Receiving messages ({}): {}",
                    receiveFromAlias,
                    LogPrinter.toHumanReadableOneLine(layerConfigurationList));
        }

        layerConfigurationList = createSendConfiguration(forwardToContext, layerStackReceiveResult);

        try {
            layerStackReceiveResult =
                    receiveFromContext.getLayerStack().sendData(layerConfigurationList);
        } catch (IOException e) {
            forwardToContext.setReceivedTransportHandlerException(true);
            LOGGER.debug(e);
        }

        try {
            layerStackSendResult =
                    forwardToContext.getLayerStack().sendData(layerConfigurationList);
        } catch (IOException e) {
            forwardToContext.setReceivedTransportHandlerException(true);
            LOGGER.debug(e);
        }
        setExecuted(true);
    }

    @Override
    public boolean executedAsPlanned() {
        return layerStackReceiveResult.executedAsPlanned()
                && layerStackSendResult.executedAsPlanned();
    }

    @Override
    public void reset() {
        layerStackReceiveResult = null;
        layerStackSendResult = null;
        setExecuted(null);
    }

    @Override
    public Set<String> getAllAliases() {
        Set<String> aliases = new LinkedHashSet<>();
        aliases.add(forwardToAlias);
        aliases.add(receiveFromAlias);
        return aliases;
    }

    @Override
    public Set<String> getAllSendingAliases() {
        return new HashSet<>(Collections.singleton(forwardToAlias));
    }

    @Override
    public Set<String> getAllReceivingAliases() {
        return new HashSet<>(Collections.singleton(receiveFromAlias));
    }

    @Override
    public void assertAliasesSetProperly() throws ConfigurationException {
        if ((receiveFromAlias == null) || (receiveFromAlias.isEmpty())) {
            throw new ActionExecutionException(
                    "Can't execute "
                            + this.getClass().getSimpleName()
                            + " with empty receive alias (if using XML: add <from/>)");
        }
        if ((forwardToAlias == null) || (forwardToAlias.isEmpty())) {
            throw new ActionExecutionException(
                    "Can't execute "
                            + this.getClass().getSimpleName()
                            + " with empty forward alis (if using XML: add <to/>)");
        }
    }

    /**
     * Create a layer configuration for the receive action. This function takes the tls context as
     * input as the configuration can depend on the current state of the connection. Note that this
     * function may change the context, and therefore, calling it twice in a row may lead to
     * distinct configurations. If an action does not wish to send messages, it can return null
     * here.
     *
     * @param tlsContext The current TLS context.
     * @return A list of layer configurations that should be executed.
     */
    protected abstract List<LayerConfiguration<?>> createReceiveConfiguration(
            TlsContext tlsContext);

    /**
     * Create a layer configuration for the send action. The received messaged messages are
     * contained in the received result. This function takes the tls context as input as the
     * configuration can depend on the current state of the connection. Note that this function may
     * change the context, and therefore, calling it twice in a row may lead to distinct
     * configurations. If an action does not wish to send messages, it can return null here.
     *
     * @param tlsContext
     * @param receivedResult
     * @return
     */
    protected abstract List<LayerConfiguration<?>> createSendConfiguration(
            TlsContext tlsContext, LayerStackProcessingResult receivedResult);

    @Override
    public List<ProtocolMessage> getReceivedMessages() {
        if (layerStackReceiveResult == null) {
            return null;
        }
        return ActionHelperUtil.getDataContainersForLayer(
                        ImplementedLayers.MESSAGE, layerStackReceiveResult)
                .stream()
                .map(container -> (ProtocolMessage) container)
                .collect(Collectors.toList());
    }

    @Override
    public List<Record> getReceivedRecords() {
        if (layerStackReceiveResult == null) {
            return null;
        }
        return ActionHelperUtil.getDataContainersForLayer(
                        ImplementedLayers.RECORD, layerStackReceiveResult)
                .stream()
                .map(container -> (Record) container)
                .collect(Collectors.toList());
    }

    @Override
    public List<DtlsHandshakeMessageFragment> getReceivedFragments() {
        if (layerStackReceiveResult == null) {
            return null;
        }
        return ActionHelperUtil.getDataContainersForLayer(
                        ImplementedLayers.DTLS_FRAGMENT, layerStackReceiveResult)
                .stream()
                .map(container -> (DtlsHandshakeMessageFragment) container)
                .collect(Collectors.toList());
    }

    @Override
    public List<HttpMessage> getReceivedHttpMessages() {
        if (layerStackReceiveResult == null) {
            return null;
        }
        return ActionHelperUtil.getDataContainersForLayer(
                        ImplementedLayers.HTTP, layerStackReceiveResult)
                .stream()
                .map(container -> (HttpMessage) container)
                .collect(Collectors.toList());
    }

    @Override
    public List<QuicFrame> getReceivedQuicFrames() {
        if (layerStackReceiveResult == null) {
            return null;
        }
        return ActionHelperUtil.getDataContainersForLayer(
                        ImplementedLayers.QUICFRAME, layerStackReceiveResult)
                .stream()
                .map(container -> (QuicFrame) container)
                .collect(Collectors.toList());
    }

    @Override
    public List<QuicPacket> getReceivedQuicPackets() {
        if (layerStackReceiveResult == null) {
            return null;
        }
        return ActionHelperUtil.getDataContainersForLayer(
                        ImplementedLayers.QUICPACKET, layerStackReceiveResult)
                .stream()
                .map(container -> (QuicPacket) container)
                .collect(Collectors.toList());
    }

    @Override
    public final List<DtlsHandshakeMessageFragment> getSentFragments() {
        if (layerStackSendResult == null) {
            return null;
        }
        return ActionHelperUtil.getDataContainersForLayer(
                        ImplementedLayers.DTLS_FRAGMENT, layerStackSendResult)
                .stream()
                .map(container -> (DtlsHandshakeMessageFragment) container)
                .collect(Collectors.toList());
    }

    @Override
    public final List<ProtocolMessage> getSentMessages() {
        if (layerStackSendResult == null) {
            return null;
        }
        return ActionHelperUtil.getDataContainersForLayer(
                        ImplementedLayers.MESSAGE, layerStackSendResult)
                .stream()
                .map(container -> (ProtocolMessage) container)
                .collect(Collectors.toList());
    }

    @Override
    public final List<QuicFrame> getSentQuicFrames() {
        if (layerStackSendResult == null) {
            return null;
        }
        return ActionHelperUtil.getDataContainersForLayer(
                        ImplementedLayers.QUICFRAME, layerStackSendResult)
                .stream()
                .map(container -> (QuicFrame) container)
                .collect(Collectors.toList());
    }

    @Override
    public final List<QuicPacket> getSentQuicPackets() {
        if (layerStackSendResult == null) {
            return null;
        }
        return ActionHelperUtil.getDataContainersForLayer(
                        ImplementedLayers.QUICPACKET, layerStackSendResult)
                .stream()
                .map(container -> (QuicPacket) container)
                .collect(Collectors.toList());
    }

    @Override
    public final List<Record> getSentRecords() {
        if (layerStackSendResult == null) {
            return null;
        }
        return ActionHelperUtil.getDataContainersForLayer(
                        ImplementedLayers.RECORD, layerStackSendResult)
                .stream()
                .map(container -> (Record) container)
                .collect(Collectors.toList());
    }
}
