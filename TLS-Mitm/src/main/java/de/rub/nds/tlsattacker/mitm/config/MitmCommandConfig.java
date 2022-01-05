/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.mitm.config;

import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class MitmCommandConfig extends TLSDelegateConfig {

    private static final Logger LOGGER = LogManager.getLogger();

    public static final String COMMAND = "mitm";

    @ParametersDelegate
    private CipherSuiteDelegate ciphersuiteDelegate;
    @ParametersDelegate
    private ProtocolVersionDelegate protocolVersionDelegate;
    @ParametersDelegate
    private NamedGroupsDelegate ellipticCurveDelegate;
    @ParametersDelegate
    private MitmDelegate mitmDelegate;
    @ParametersDelegate
    private SignatureAndHashAlgorithmDelegate signatureAndHashAlgorithmDelegate;
    @ParametersDelegate
    private WorkflowInputDelegate workflowInputDelegate;
    @ParametersDelegate
    private WorkflowOutputDelegate workflowOutputDelegate;
    @ParametersDelegate
    private MitmWorkflowTypeDelegate mitmWorkflowTypeDelegate;
    @ParametersDelegate
    private TransportHandlerDelegate transportHandlerDelegate;
    @ParametersDelegate
    private HeartbeatDelegate heartbeatDelegate;
    @ParametersDelegate
    private MaxFragmentLengthDelegate maxFragmentLengthDelegate;
    @ParametersDelegate
    private CertificateDelegate certificateDelegate;
    @ParametersDelegate
    private FilterDelegate filterDelegate;
    @ParametersDelegate
    private ListDelegate listDelegate;
    @ParametersDelegate
    private ConfigOutputDelegate configOutputDelegate;
    @ParametersDelegate
    private TimeoutDelegate timeoutDelegate;
    @ParametersDelegate
    private ExecutorTypeDelegate executorTypeDelegate;

    public MitmCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        this.ciphersuiteDelegate = new CipherSuiteDelegate();
        this.heartbeatDelegate = new HeartbeatDelegate();
        this.ellipticCurveDelegate = new NamedGroupsDelegate();
        this.protocolVersionDelegate = new ProtocolVersionDelegate();
        this.mitmDelegate = new MitmDelegate();
        this.signatureAndHashAlgorithmDelegate = new SignatureAndHashAlgorithmDelegate();
        this.transportHandlerDelegate = new TransportHandlerDelegate();
        this.workflowOutputDelegate = new WorkflowOutputDelegate();
        this.workflowInputDelegate = new WorkflowInputDelegate();
        this.mitmWorkflowTypeDelegate = new MitmWorkflowTypeDelegate();
        this.maxFragmentLengthDelegate = new MaxFragmentLengthDelegate();
        this.certificateDelegate = new CertificateDelegate();
        this.filterDelegate = new FilterDelegate();
        this.listDelegate = new ListDelegate();
        this.configOutputDelegate = new ConfigOutputDelegate();
        this.timeoutDelegate = new TimeoutDelegate();
        this.executorTypeDelegate = new ExecutorTypeDelegate();

        addDelegate(maxFragmentLengthDelegate);
        addDelegate(ciphersuiteDelegate);
        addDelegate(ellipticCurveDelegate);
        addDelegate(protocolVersionDelegate);
        addDelegate(mitmDelegate);
        addDelegate(signatureAndHashAlgorithmDelegate);
        addDelegate(heartbeatDelegate);
        addDelegate(transportHandlerDelegate);
        addDelegate(certificateDelegate);
        addDelegate(workflowInputDelegate);
        addDelegate(workflowOutputDelegate);
        addDelegate(mitmWorkflowTypeDelegate);
        addDelegate(filterDelegate);
        addDelegate(listDelegate);
        addDelegate(configOutputDelegate);
        addDelegate(timeoutDelegate);
        addDelegate(executorTypeDelegate);
    }
}
