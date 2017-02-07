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
import de.rub.nds.tlsattacker.tls.config.converters.BigIntegerConverter;
import de.rub.nds.tlsattacker.tls.config.delegate.CiphersuiteDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.HostnameExtensionDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.ProtocolVersionDelegate;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import java.math.BigInteger;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class WinshockCommandConfig extends TLSDelegateConfig {

    public static final String ATTACK_COMMAND = "winshock";
    @ParametersDelegate
    private ClientDelegate clientDelegate;
    @ParametersDelegate
    private HostnameExtensionDelegate hostnameExtensionDelegate;
    @ParametersDelegate
    private CiphersuiteDelegate ciphersuiteDelegate;
    @ParametersDelegate
    private ProtocolVersionDelegate protocolVersionDelegate;

    @Parameter(names = "-signature_length", description = "Length of the signature in the CertificateVerify protocol message")
    Integer signatureLength;

    @Parameter(names = "-signature", description = "Signature value in the CertificateVerify protocol message", converter = BigIntegerConverter.class, required = true)
    BigInteger signature;

    public WinshockCommandConfig() {
        clientDelegate = new ClientDelegate();
        hostnameExtensionDelegate = new HostnameExtensionDelegate();
        ciphersuiteDelegate = new CiphersuiteDelegate();
        protocolVersionDelegate = new ProtocolVersionDelegate();
        addDelegate(hostnameExtensionDelegate);
        addDelegate(ciphersuiteDelegate);
        addDelegate(protocolVersionDelegate);
        addDelegate(clientDelegate);
    }

    public Integer getSignatureLength() {
        return signatureLength;
    }

    public void setSignatureLength(Integer signatureLength) {
        this.signatureLength = signatureLength;
    }

    public BigInteger getSignature() {
        return signature;
    }

    public void setSignature(BigInteger signature) {
        this.signature = signature;
    }

}
