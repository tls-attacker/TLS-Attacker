/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.container.ActionHelperUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;
import java.util.StringJoiner;

@XmlRootElement(name = "SendDynamicClientKeyExchange")
public class SendDynamicClientKeyExchangeAction extends CommonSendAction {

    private List<DtlsHandshakeMessageFragment> configuredFragmentList = null;

    public SendDynamicClientKeyExchangeAction() {
        super();
    }

    public SendDynamicClientKeyExchangeAction(String connectionAlias) {
        super(connectionAlias);
    }

    public List<DtlsHandshakeMessageFragment> getConfiguredFragmentList() {
        return configuredFragmentList;
    }

    public void setConfiguredFragmentList(
            List<DtlsHandshakeMessageFragment> configuredFragmentList) {
        this.configuredFragmentList = configuredFragmentList;
    }

    @Override
    public String toString() {
        StringBuilder sb;
        if (isExecuted()) {
            sb = new StringBuilder("Send Dynamic Client Key Exchange Action:\n");
            sb.append("\tMessages:");
            if (getSentMessages() != null) {
                StringJoiner joiner = new StringJoiner(", ");
                for (ProtocolMessage message : getSentMessages()) {
                    joiner.add(message.toCompactString());
                }
                sb.append(joiner.toString());
            } else {
                sb.append("null (no messages set)");
            }
        } else {
            sb = new StringBuilder("Send Dynamic Client Key Exchange Action: (not executed)\n");
        }

        return sb.toString();
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder(super.toCompactString());
        if ((getSentMessages() != null) && (!getSentMessages().isEmpty())) {
            sb.append(" (");
            StringJoiner joiner = new StringJoiner(", ");
            for (ProtocolMessage message : getSentMessages()) {
                joiner.add(message.toCompactString());
            }
            sb.append(joiner.toString());
            sb.append(")");
        } else {
            sb.append(" (no messages set)");
        }
        return sb.toString();
    }

    @Override
    protected List<LayerConfiguration<?>> createLayerConfiguration(State state) {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());
        ClientKeyExchangeMessage clientKeyExchangeMessage = new WorkflowConfigurationFactory(tlsContext.getConfig())
                .createClientKeyExchangeMessage(
                        tlsContext.getChooser().getSelectedCipherSuite().getKeyExchangeAlgorithm());
        if (clientKeyExchangeMessage != null) {
            List<LayerConfiguration<?>> configurationList = new LinkedList<>();
            configurationList.add(
                    new SpecificSendLayerConfiguration<>(
                            ImplementedLayers.MESSAGE, clientKeyExchangeMessage));
            if (configuredFragmentList != null) {
                configurationList.add(
                        new SpecificSendLayerConfiguration<>(
                                ImplementedLayers.DTLS_FRAGMENT, configuredFragmentList));
            }
            return ActionHelperUtil.sortAndAddOptions(
                    tlsContext.getLayerStack(), true, getActionOptions(), configurationList);

        } else {
            return null;
        }
    }
}
