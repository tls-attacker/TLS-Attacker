/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.client.config;

import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.CertificateDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.CiphersuiteDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.EllipticCurveDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.HeartbeatDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.HostnameExtensionDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.MaxFragmentLengthDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ProtocolVersionDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.SignatureAndHashAlgorithmDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.TransportHandlerDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.WorkflowInputDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.WorkflowOutputDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.WorkflowTypeDelegate;
import de.rub.nds.tlsattacker.core.config.TlsConfig;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ClientCommandConfig extends TLSDelegateConfig {

    public static final String COMMAND = "client";

    @ParametersDelegate
    private final GeneralDelegate generalDelegate;
    @ParametersDelegate
    private final CiphersuiteDelegate ciphersuiteDelegate;
    @ParametersDelegate
    private final HostnameExtensionDelegate hostnameExtensionDelegate;
    @ParametersDelegate
    private final MaxFragmentLengthDelegate maxFragmentLengthDelegate;
    @ParametersDelegate
    private final ProtocolVersionDelegate protocolVersionDelegate;
    @ParametersDelegate
    private final EllipticCurveDelegate ellipticCurveDelegate;
    @ParametersDelegate
    private final ClientDelegate clientDelegate;
    @ParametersDelegate
    private final SignatureAndHashAlgorithmDelegate signatureAndHashAlgorithmDelegate;
    @ParametersDelegate
    private final TransportHandlerDelegate transportHandlerDelegate;
    @ParametersDelegate
    private final WorkflowInputDelegate workflowInputDelegate;
    @ParametersDelegate
    private final WorkflowOutputDelegate workflowOutputDelegate;
    @ParametersDelegate
    private final WorkflowTypeDelegate workflowTypeDelegate;
    @ParametersDelegate
    private final HeartbeatDelegate heartbeatDelegate;
    @ParametersDelegate
    private final CertificateDelegate certificateDelegate;

    public ClientCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        this.generalDelegate = delegate;
        this.ciphersuiteDelegate = new CiphersuiteDelegate();
        this.maxFragmentLengthDelegate = new MaxFragmentLengthDelegate();
        this.hostnameExtensionDelegate = new HostnameExtensionDelegate();
        this.ellipticCurveDelegate = new EllipticCurveDelegate();
        this.protocolVersionDelegate = new ProtocolVersionDelegate();
        this.clientDelegate = new ClientDelegate();
        this.signatureAndHashAlgorithmDelegate = new SignatureAndHashAlgorithmDelegate();
        this.transportHandlerDelegate = new TransportHandlerDelegate();
        this.workflowInputDelegate = new WorkflowInputDelegate();
        this.workflowOutputDelegate = new WorkflowOutputDelegate();
        this.workflowTypeDelegate = new WorkflowTypeDelegate();
        this.heartbeatDelegate = new HeartbeatDelegate();
        this.certificateDelegate = new CertificateDelegate();
        addDelegate(heartbeatDelegate);
        addDelegate(ciphersuiteDelegate);
        addDelegate(maxFragmentLengthDelegate);
        addDelegate(hostnameExtensionDelegate);
        addDelegate(ellipticCurveDelegate);
        addDelegate(protocolVersionDelegate);
        addDelegate(clientDelegate);
        addDelegate(signatureAndHashAlgorithmDelegate);
        addDelegate(workflowInputDelegate);
        addDelegate(workflowOutputDelegate);
        addDelegate(workflowTypeDelegate);
        addDelegate(transportHandlerDelegate);
        addDelegate(certificateDelegate);
    }

    @Override
    public TlsConfig createConfig() {
        TlsConfig config = super.createConfig();
        if (config.getWorkflowTrace() == null) {
            config.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
        }
        return config;
    }
}
