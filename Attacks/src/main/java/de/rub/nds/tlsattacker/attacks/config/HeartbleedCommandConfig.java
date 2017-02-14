/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.tls.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.tls.config.delegate.CiphersuiteDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.HostnameExtensionDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.ProtocolVersionDelegate;
import de.rub.nds.tlsattacker.tls.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTraceType;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class HeartbleedCommandConfig extends TLSDelegateConfig {

    public static final String ATTACK_COMMAND = "heartbleed";

    @Parameter(names = "-payload_length", description = "Payload length sent in the client heartbeat message")
    Integer payloadLength = 20000;

    @ParametersDelegate
    private final ClientDelegate clientDelegate;
    @ParametersDelegate
    private final HostnameExtensionDelegate hostnameExtensionDelegate;
    @ParametersDelegate
    private final CiphersuiteDelegate ciphersuiteDelegate;
    @ParametersDelegate
    private final ProtocolVersionDelegate protocolVersionDelegate;

    public HeartbleedCommandConfig() {
        clientDelegate = new ClientDelegate();
        hostnameExtensionDelegate = new HostnameExtensionDelegate();
        ciphersuiteDelegate = new CiphersuiteDelegate();
        protocolVersionDelegate = new ProtocolVersionDelegate();
        addDelegate(clientDelegate);
        addDelegate(hostnameExtensionDelegate);
        addDelegate(ciphersuiteDelegate);
        addDelegate(protocolVersionDelegate);
    }

    public Integer getPayloadLength() {
        return payloadLength;
    }

    public void setPayloadLength(Integer payloadLength) {
        this.payloadLength = payloadLength;
    }

    @Override
    public TlsConfig createConfig() {
        TlsConfig config = super.createConfig();
        config.setWorkflowTraceType(WorkflowTraceType.FULL);
        config.setHeartbeatMode(HeartbeatMode.PEER_ALLOWED_TO_SEND);
        return config;
    }
}
