/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.container.ActionHelperUtil;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement(name = "SendDynamicServerCertificate")
public class SendDynamicServerCertificateAction extends CommonSendAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public SendDynamicServerCertificateAction() {
        super();
    }

    public SendDynamicServerCertificateAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public String toString() {
        StringBuilder sb;
        if (isExecuted()) {
            sb = new StringBuilder("Send Dynamic Certificate Action:\n");
            sb.append("\tMessages:");
            if (getSentMessages() != null) {
                for (ProtocolMessage message : getSentMessages()) {
                    sb.append(message.toCompactString());
                    sb.append(", ");
                }
                sb.append("\n");
            } else {
                sb.append("null (no messages set)");
            }
        } else {
            sb = new StringBuilder("Send Dynamic Certificate: (not executed)\n");
        }

        return sb.toString();
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder(super.toCompactString());
        if ((getSentMessages() != null) && (!getSentMessages().isEmpty())) {
            sb.append(" (");
            for (ProtocolMessage message : getSentMessages()) {
                sb.append(message.toCompactString());
                sb.append(",");
            }
            sb.deleteCharAt(sb.lastIndexOf(",")).append(")");
        } else {
            sb.append(" (no messages set)");
        }
        return sb.toString();
    }

    @Override
    protected List<LayerConfiguration<?>> createLayerConfiguration(State state) {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());
        CipherSuite selectedCipherSuite = tlsContext.getChooser().getSelectedCipherSuite();
        if (selectedCipherSuite.requiresServerCertificateMessage()) {
            List<LayerConfiguration<?>> configurationList = new LinkedList<>();
            configurationList.add(
                    new SpecificSendLayerConfiguration<>(
                            ImplementedLayers.MESSAGE, new CertificateMessage()));
            return ActionHelperUtil.sortAndAddOptions(
                    tlsContext.getLayerStack(), true, getActionOptions(), configurationList);

        } else {
            return null;
        }
    }
}
