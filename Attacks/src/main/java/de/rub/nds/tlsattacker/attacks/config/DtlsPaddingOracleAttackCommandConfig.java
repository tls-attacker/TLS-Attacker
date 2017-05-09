/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.CiphersuiteDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.HostnameExtensionDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ProtocolVersionDelegate;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 */
public class DtlsPaddingOracleAttackCommandConfig extends AttackConfig {

    public static final String ATTACK_COMMAND = "dtls_potest";

    @Parameter(names = "-messagespertrain", description = "Number of messages per train")
    private int messagesPerTrain = 10;

    @Parameter(names = "-trainmessagesize", description = "Message size of each trains messages")
    private int trainMessageSize = 1450;

    @Parameter(names = "-rounds", description = "Number of attack rounds")
    private int nrOfRounds = 20;

    @Parameter(names = "-resultfile", description = "Save the response times in the specified file")
    private String resultFilePath = null;

    @Parameter(names = "-messagewaitnanos", description = "Wait for this amount of nanoseconds between sending two messages of any given train (rate limiting)")
    private long messageWaitNanos = 0;

    @ParametersDelegate
    private final ClientDelegate clientDelegate;
    @ParametersDelegate
    private final HostnameExtensionDelegate hostnameExtensionDelegate;
    @ParametersDelegate
    private final CiphersuiteDelegate ciphersuiteDelegate;
    @ParametersDelegate
    private final ProtocolVersionDelegate protocolVersionDelegate;

    public DtlsPaddingOracleAttackCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        clientDelegate = new ClientDelegate();
        hostnameExtensionDelegate = new HostnameExtensionDelegate();
        ciphersuiteDelegate = new CiphersuiteDelegate();
        protocolVersionDelegate = new ProtocolVersionDelegate();
        addDelegate(clientDelegate);
        addDelegate(hostnameExtensionDelegate);
        addDelegate(ciphersuiteDelegate);
        addDelegate(protocolVersionDelegate);
    }

    public int getMessagesPerTrain() {
        return messagesPerTrain;
    }

    public int getTrainMessageSize() {
        return trainMessageSize;
    }

    public int getNrOfRounds() {
        return nrOfRounds;
    }

    public String getResultFilePath() {
        return resultFilePath;
    }

    public long getMessageWaitNanos() {
        return messageWaitNanos;
    }

    public void setMessagesPerTrain(int messagesPerTrain) {
        this.messagesPerTrain = messagesPerTrain;
    }

    public void setTrainMessageSize(int trainMessageSize) {
        this.trainMessageSize = trainMessageSize;
    }

    public void setNrOfRounds(int nrOfRounds) {
        this.nrOfRounds = nrOfRounds;
    }

    public void setResultFilePath(String resultFilePath) {
        this.resultFilePath = resultFilePath;
    }

    public void setMessageWaitNanos(long messageWaitNanos) {
        this.messageWaitNanos = messageWaitNanos;
    }

    @Override
    public TlsConfig createConfig() {
        TlsConfig config = super.createConfig();
        config.setTransportHandlerType(TransportHandlerType.UDP);
        config.setHighestProtocolVersion(ProtocolVersion.DTLS12);
        config.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);

        // Until all dtls workflow factories are adapted, this is to make sure
        // the right workflow factory is used //TODO what?!
        List<CipherSuite> cs = new ArrayList<>();
        if (ciphersuiteDelegate.getCipherSuites() == null) {
            cs.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
            config.setSupportedCiphersuites(cs);
        }
        return config;
    }
}
