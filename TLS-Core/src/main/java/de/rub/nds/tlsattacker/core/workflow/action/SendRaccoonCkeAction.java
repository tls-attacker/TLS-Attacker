/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.core.workflow.container.ActionHelperUtil;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement(name = "SendRaccoonCke")
public class SendRaccoonCkeAction extends CommonSendAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private boolean withNullByte = true;

    private BigInteger initialSecret = new BigInteger("5000");

    public SendRaccoonCkeAction() {
        super();
    }

    public SendRaccoonCkeAction(boolean withNullByte, BigInteger initialSecret) {
        super();
        this.withNullByte = withNullByte;
        this.initialSecret = initialSecret;
    }

    public SendRaccoonCkeAction(String connectionAlias) {
        super(connectionAlias);
    }

    public BigInteger getInitialSecret() {
        return initialSecret;
    }

    public void setInitialSecret(BigInteger initialSecret) {
        this.initialSecret = initialSecret;
    }

    public boolean isWithNullByte() {
        return withNullByte;
    }

    public void setWithNullByte(boolean withNullByte) {
        this.withNullByte = withNullByte;
    }

    private DHClientKeyExchangeMessage generateRaccoonDhClientKeyExchangeMessage(
            TlsContext context, boolean withNullByte) {

        DHClientKeyExchangeMessage cke = new DHClientKeyExchangeMessage();
        Chooser chooser = context.getChooser();
        byte[] clientPublicKey;
        if (chooser.getSelectedCipherSuite().isEphemeral()) {
            clientPublicKey =
                    getClientPublicKey(
                            chooser.getServerEphemeralDhGenerator(),
                            chooser.getServerEphemeralDhModulus(),
                            chooser.getServerEphemeralDhPublicKey(),
                            initialSecret,
                            withNullByte);
        } else {
            clientPublicKey =
                    getClientPublicKey(
                            chooser.getServerX509Chooser().getSubjectDhGenerator(),
                            chooser.getServerX509Chooser().getSubjectDhModulus(),
                            chooser.getServerX509Chooser().getSubjectDhPublicKey(),
                            initialSecret,
                            withNullByte);
        }
        cke.setPublicKey(Modifiable.explicit(clientPublicKey));
        return cke;
    }

    private byte[] getClientPublicKey(
            BigInteger g,
            BigInteger m,
            BigInteger serverPublicKey,
            BigInteger initialClientDhSecret,
            boolean withNullByte) {
        int length = ArrayConverter.bigIntegerToByteArray(m).length;
        byte[] pms =
                ArrayConverter.bigIntegerToNullPaddedByteArray(
                        serverPublicKey.modPow(initialClientDhSecret, m), length);

        if (((withNullByte && pms[0] == 0) && pms[1] != 0) || (!withNullByte && pms[0] != 0)) {
            BigInteger clientPublicKey = g.modPow(initialClientDhSecret, m);
            byte[] cke = ArrayConverter.bigIntegerToByteArray(clientPublicKey);
            if (cke.length == length) {
                return cke;
            }
        }
        initialClientDhSecret = initialClientDhSecret.add(new BigInteger("1"));
        return getClientPublicKey(g, m, serverPublicKey, initialClientDhSecret, withNullByte);
    }

    @Override
    public String toString() {
        StringBuilder sb;
        if (isExecuted()) {
            sb = new StringBuilder("Send Raccoon DH-CKE Action:\n");
        } else {
            sb = new StringBuilder("Send Raccoon DH-CKE: (not executed)\n");
        }
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
        ClientKeyExchangeMessage message =
                generateRaccoonDhClientKeyExchangeMessage(tlsContext, withNullByte);
        List<LayerConfiguration<?>> configurationList = new LinkedList<>();
        configurationList.add(
                new SpecificSendLayerConfiguration<>(ImplementedLayers.MESSAGE, message));
        return ActionHelperUtil.sortAndAddOptions(
                tlsContext.getLayerStack(), true, getActionOptions(), configurationList);
    }
}
