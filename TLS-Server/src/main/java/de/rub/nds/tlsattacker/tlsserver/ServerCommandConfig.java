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
import de.rub.nds.tlsattacker.tls.config.delegate.CiphersuiteDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.CompressionDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.EllipticCurveDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.HostnameExtensionDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.ProtocolVersionDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.ServerDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.SignatureAndHashAlgorithmDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.TimeoutDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.TransportHandlerDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.WorkflowInputDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.WorkflowOutputDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.WorkflowTypeDelegate;

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
    private final CompressionDelegate compressionDelegate;
    @ParametersDelegate
    private final HostnameExtensionDelegate hostnameExtensionDelegate;
    @ParametersDelegate
    private final ProtocolVersionDelegate protocolVersionDelegate;
    @ParametersDelegate
    private final EllipticCurveDelegate ellipticCurveDelegate;
    @ParametersDelegate
    private final ServerDelegate serverDelegate;
    @ParametersDelegate
    private final SignatureAndHashAlgorithmDelegate signatureAndHashAlgorithmDelegate;
    @ParametersDelegate
    private final TimeoutDelegate timeoutDelegate;
    @ParametersDelegate
    private final TransportHandlerDelegate transportHandlerDelegate;
    @ParametersDelegate
    private final WorkflowInputDelegate workflowInputDelegate;
    @ParametersDelegate
    private final WorkflowOutputDelegate workflowOutputDelegate;
    @ParametersDelegate
    private final WorkflowTypeDelegate workflowTypeDelegate;

    public ServerCommandConfig() {
        super();
        this.ciphersuiteDelegate = new CiphersuiteDelegate();
        this.compressionDelegate = new CompressionDelegate();
        this.hostnameExtensionDelegate = new HostnameExtensionDelegate();
        this.ellipticCurveDelegate = new EllipticCurveDelegate();
        this.protocolVersionDelegate = new ProtocolVersionDelegate();
        this.serverDelegate = new ServerDelegate();
        this.signatureAndHashAlgorithmDelegate = new SignatureAndHashAlgorithmDelegate();
        this.timeoutDelegate = new TimeoutDelegate();
        this.transportHandlerDelegate = new TransportHandlerDelegate();
        this.workflowInputDelegate = new WorkflowInputDelegate();
        this.workflowOutputDelegate = new WorkflowOutputDelegate();
        this.workflowTypeDelegate = new WorkflowTypeDelegate();
        addDelegate(ciphersuiteDelegate);
        addDelegate(compressionDelegate);
        addDelegate(hostnameExtensionDelegate);
        addDelegate(ellipticCurveDelegate);
        addDelegate(protocolVersionDelegate);
        addDelegate(serverDelegate);
        addDelegate(signatureAndHashAlgorithmDelegate);
        addDelegate(timeoutDelegate);
        addDelegate(transportHandlerDelegate);
        addDelegate(workflowInputDelegate);
        addDelegate(workflowOutputDelegate);
        addDelegate(workflowTypeDelegate);

    }
}
