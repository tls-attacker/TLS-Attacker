/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.server.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.*;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;

public class ServerCommandConfig extends TLSDelegateConfig {

    public static final String COMMAND = "server";

    @ParametersDelegate private CipherSuiteDelegate ciphersuiteDelegate;
    @ParametersDelegate private ProtocolVersionDelegate protocolVersionDelegate;
    @ParametersDelegate private NamedGroupsDelegate ellipticCurveDelegate;
    @ParametersDelegate private ServerDelegate serverDelegate;
    @ParametersDelegate private SignatureAndHashAlgorithmDelegate signatureAndHashAlgorithmDelegate;
    @ParametersDelegate private SignatureAlgorithmCertDelegate signatureAlgorithmCertDelegate;
    @ParametersDelegate private WorkflowTypeDelegate workflowTypeDelegate;
    @ParametersDelegate private TransportHandlerDelegate transportHandlerDelegate;
    @ParametersDelegate private HeartbeatDelegate heartbeatDelegate;
    @ParametersDelegate private MaxFragmentLengthDelegate maxFragmentLengthDelegate;
    @ParametersDelegate private CertificateDelegate certificateDelegate;
    @ParametersDelegate private FilterDelegate filterDelegate;
    @ParametersDelegate private ListDelegate listDelegate;
    @ParametersDelegate private ExecutorTypeDelegate executorTypeDelegate;
    @ParametersDelegate private StarttlsDelegate starttlsDelegate;
    @ParametersDelegate private TimeoutDelegate timeoutDelegate;

    @Parameter(
            names = "-workflow_input",
            description = "A path to a workflow trace that should be exeucted")
    private String workflowInput = null;

    @Parameter(
            names = "-workflow_output",
            description = "A path in which the executed workflow trace should be stored in")
    private String workflowOutput = null;

    public ServerCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        this.ciphersuiteDelegate = new CipherSuiteDelegate();
        this.heartbeatDelegate = new HeartbeatDelegate();
        this.ellipticCurveDelegate = new NamedGroupsDelegate();
        this.protocolVersionDelegate = new ProtocolVersionDelegate();
        this.serverDelegate = new ServerDelegate();
        this.signatureAndHashAlgorithmDelegate = new SignatureAndHashAlgorithmDelegate();
        this.signatureAlgorithmCertDelegate = new SignatureAlgorithmCertDelegate();
        this.transportHandlerDelegate = new TransportHandlerDelegate();
        this.workflowTypeDelegate = new WorkflowTypeDelegate();
        this.maxFragmentLengthDelegate = new MaxFragmentLengthDelegate();
        this.certificateDelegate = new CertificateDelegate();
        this.filterDelegate = new FilterDelegate();
        this.listDelegate = new ListDelegate();
        this.executorTypeDelegate = new ExecutorTypeDelegate();
        this.starttlsDelegate = new StarttlsDelegate();
        this.timeoutDelegate = new TimeoutDelegate();
        addDelegate(maxFragmentLengthDelegate);
        addDelegate(ciphersuiteDelegate);
        addDelegate(ellipticCurveDelegate);
        addDelegate(protocolVersionDelegate);
        addDelegate(serverDelegate);
        addDelegate(signatureAndHashAlgorithmDelegate);
        addDelegate(signatureAlgorithmCertDelegate);
        addDelegate(heartbeatDelegate);
        addDelegate(workflowTypeDelegate);
        addDelegate(transportHandlerDelegate);
        addDelegate(certificateDelegate);
        addDelegate(filterDelegate);
        addDelegate(listDelegate);
        addDelegate(executorTypeDelegate);
        addDelegate(starttlsDelegate);
        addDelegate(timeoutDelegate);
    }

    @Override
    public Config createConfig() {
        Config config = super.createConfig();

        if (config.getWorkflowTraceType() == null) {
            config.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
        }
        return config;
    }

    public String getWorkflowInput() {
        return workflowInput;
    }

    public String getWorkflowOutput() {
        return workflowOutput;
    }
}
