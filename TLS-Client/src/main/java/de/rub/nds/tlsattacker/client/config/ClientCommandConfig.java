/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.client.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.*;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;

public class ClientCommandConfig extends TLSDelegateConfig {

    public static final String COMMAND = "client";

    @ParametersDelegate private CipherSuiteDelegate ciphersuiteDelegate;
    @ParametersDelegate private CompressionDelegate compressionDelegate;
    @ParametersDelegate private MaxFragmentLengthDelegate maxFragmentLengthDelegate;
    @ParametersDelegate private ProtocolVersionDelegate protocolVersionDelegate;
    @ParametersDelegate private NamedGroupsDelegate ellipticCurveDelegate;
    @ParametersDelegate private ClientDelegate clientDelegate;
    @ParametersDelegate private SignatureAndHashAlgorithmDelegate signatureAndHashAlgorithmDelegate;
    @ParametersDelegate private SignatureAlgorithmCertDelegate signatureAlgorithmCertDelegate;
    @ParametersDelegate private TransportHandlerDelegate transportHandlerDelegate;
    @ParametersDelegate private TimeoutDelegate timeoutDelegate;
    @ParametersDelegate private WorkflowTypeDelegate workflowTypeDelegate;
    @ParametersDelegate private HeartbeatDelegate heartbeatDelegate;
    @ParametersDelegate private CertificateDelegate certificateDelegate;
    @ParametersDelegate private FilterDelegate filterDelegate;
    @ParametersDelegate private ListDelegate listDelegate;
    @ParametersDelegate private StarttlsDelegate starttlsDelegate;

    @ParametersDelegate private EchDelegate echDelegate;

    @Parameter(
            names = "-workflow_input",
            description = "A path to a workflow trace that should be exeucted")
    private String workflowInput = null;

    @Parameter(
            names = "-workflow_output",
            description = "A path in which the executed workflow trace should be stored in")
    private String workflowOutput = null;

    public ClientCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        this.ciphersuiteDelegate = new CipherSuiteDelegate();
        this.maxFragmentLengthDelegate = new MaxFragmentLengthDelegate();
        this.ellipticCurveDelegate = new NamedGroupsDelegate();
        this.protocolVersionDelegate = new ProtocolVersionDelegate();
        this.clientDelegate = new ClientDelegate();
        this.signatureAndHashAlgorithmDelegate = new SignatureAndHashAlgorithmDelegate();
        this.signatureAlgorithmCertDelegate = new SignatureAlgorithmCertDelegate();
        this.transportHandlerDelegate = new TransportHandlerDelegate();
        this.timeoutDelegate = new TimeoutDelegate();
        this.workflowTypeDelegate = new WorkflowTypeDelegate();
        this.heartbeatDelegate = new HeartbeatDelegate();
        this.certificateDelegate = new CertificateDelegate();
        this.filterDelegate = new FilterDelegate();
        this.listDelegate = new ListDelegate();
        this.starttlsDelegate = new StarttlsDelegate();
        this.compressionDelegate = new CompressionDelegate();
        this.echDelegate = new EchDelegate();
        addDelegate(listDelegate);
        addDelegate(heartbeatDelegate);
        addDelegate(ciphersuiteDelegate);
        addDelegate(compressionDelegate);
        addDelegate(maxFragmentLengthDelegate);
        addDelegate(ellipticCurveDelegate);
        addDelegate(protocolVersionDelegate);
        addDelegate(clientDelegate);
        addDelegate(signatureAndHashAlgorithmDelegate);
        addDelegate(signatureAlgorithmCertDelegate);
        addDelegate(workflowTypeDelegate);
        addDelegate(transportHandlerDelegate);
        addDelegate(timeoutDelegate);
        addDelegate(certificateDelegate);
        addDelegate(filterDelegate);
        addDelegate(starttlsDelegate);
        addDelegate(echDelegate);
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
