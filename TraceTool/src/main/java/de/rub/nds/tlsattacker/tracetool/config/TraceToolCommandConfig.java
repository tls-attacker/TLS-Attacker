/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.tracetool.config;

import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.CipherSuiteDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ConfigOutputDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.FilterDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ListDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ProtocolVersionDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.RunningModeDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.WorkflowInputDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.WorkflowOutputDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.WorkflowTypeDelegate;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TraceToolCommandConfig extends TLSDelegateConfig {

    private static final Logger LOGGER = LogManager.getLogger();

    public static final String COMMAND = "tracetool";

    @ParametersDelegate
    private ProtocolVersionDelegate protocolVersionDelegate;
    @ParametersDelegate
    private WorkflowInputDelegate workflowInputDelegate;
    @ParametersDelegate
    private WorkflowOutputDelegate workflowOutputDelegate;
    @ParametersDelegate
    private WorkflowTypeDelegate workflowTypeDelegate;
    @ParametersDelegate
    private FilterDelegate filterDelegate;
    @ParametersDelegate
    private ConfigOutputDelegate configOutputDelegate;
    @ParametersDelegate
    private ListDelegate listDelegate;
    @ParametersDelegate
    private RunningModeDelegate runningModeDelegate;
    @ParametersDelegate
    private CipherSuiteDelegate ciphersuiteDelegate;

    public TraceToolCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        this.protocolVersionDelegate = new ProtocolVersionDelegate();
        this.workflowOutputDelegate = new WorkflowOutputDelegate();
        this.workflowInputDelegate = new WorkflowInputDelegate();
        this.workflowTypeDelegate = new WorkflowTypeDelegate();
        this.filterDelegate = new FilterDelegate();
        this.configOutputDelegate = new ConfigOutputDelegate();
        this.listDelegate = new ListDelegate();
        this.ciphersuiteDelegate = new CipherSuiteDelegate();
        this.runningModeDelegate = new RunningModeDelegate();
        addDelegate(protocolVersionDelegate);
        addDelegate(ciphersuiteDelegate);
        addDelegate(workflowInputDelegate);
        addDelegate(workflowOutputDelegate);
        addDelegate(workflowTypeDelegate);
        addDelegate(filterDelegate);
        addDelegate(configOutputDelegate);
        addDelegate(listDelegate);
        addDelegate(runningModeDelegate);
    }

    @Override
    public Config createConfig() {
        Config config = super.createConfig();

        if (config.getWorkflowTraceType() == null) {
            config.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
        }
        return config;
    }
}
