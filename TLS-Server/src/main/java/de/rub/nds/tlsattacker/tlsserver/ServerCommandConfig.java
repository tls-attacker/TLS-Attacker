/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tlsserver;

import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.tls.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.tls.config.delegate.CertificateDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.CiphersuiteDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.EllipticCurveDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.HeartbeatDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.MaxFragmentLengthDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.ProtocolVersionDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.ServerDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.SignatureAndHashAlgorithmDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.TransportHandlerDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.WorkflowInputDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.WorkflowOutputDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.WorkflowTypeDelegate;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTraceType;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class ServerCommandConfig extends TLSDelegateConfig {

    public static final String COMMAND = "server";
    @ParametersDelegate
    private final CiphersuiteDelegate ciphersuiteDelegate;
    @ParametersDelegate
    private final ProtocolVersionDelegate protocolVersionDelegate;
    @ParametersDelegate
    private final EllipticCurveDelegate ellipticCurveDelegate;
    @ParametersDelegate
    private final ServerDelegate serverDelegate;
    @ParametersDelegate
    private final SignatureAndHashAlgorithmDelegate signatureAndHashAlgorithmDelegate;
    @ParametersDelegate
    private final WorkflowInputDelegate workflowInputDelegate;
    @ParametersDelegate
    private final WorkflowOutputDelegate workflowOutputDelegate;
    @ParametersDelegate
    private final WorkflowTypeDelegate workflowTypeDelegate;
    @ParametersDelegate
    private final TransportHandlerDelegate transportHandlerDelegate;
    @ParametersDelegate
    private final HeartbeatDelegate heartbeatDelegate;
    @ParametersDelegate
    private final MaxFragmentLengthDelegate maxFragmentLengthDelegate;
    @ParametersDelegate
    private final CertificateDelegate certificateDelegate;
    
    public ServerCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        this.ciphersuiteDelegate = new CiphersuiteDelegate();
        this.heartbeatDelegate = new HeartbeatDelegate();
        this.ellipticCurveDelegate = new EllipticCurveDelegate();
        this.protocolVersionDelegate = new ProtocolVersionDelegate();
        this.serverDelegate = new ServerDelegate();
        this.signatureAndHashAlgorithmDelegate = new SignatureAndHashAlgorithmDelegate();
        this.transportHandlerDelegate = new TransportHandlerDelegate();
        this.workflowInputDelegate = new WorkflowInputDelegate();
        this.workflowOutputDelegate = new WorkflowOutputDelegate();
        this.workflowTypeDelegate = new WorkflowTypeDelegate();
        this.maxFragmentLengthDelegate = new MaxFragmentLengthDelegate();
        this.certificateDelegate = new CertificateDelegate();
        addDelegate(maxFragmentLengthDelegate);
        addDelegate(ciphersuiteDelegate);
        addDelegate(ellipticCurveDelegate);
        addDelegate(protocolVersionDelegate);
        addDelegate(serverDelegate);
        addDelegate(signatureAndHashAlgorithmDelegate);
        addDelegate(heartbeatDelegate);
        addDelegate(workflowInputDelegate);
        addDelegate(workflowOutputDelegate);
        addDelegate(workflowTypeDelegate);
        addDelegate(transportHandlerDelegate);
        addDelegate(certificateDelegate);
    }

    @Override
    public TlsConfig createConfig() {
        TlsConfig config = super.createConfig();
        if (config.getWorkflowTraceType() == null) {
            config.setWorkflowTraceType(WorkflowTraceType.FULL);
        }
        return config;
    }

}
