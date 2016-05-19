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
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.converters.BigIntegerConverter;
import java.math.BigInteger;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class WinshockCommandConfig extends ClientCommandConfig {

    public static final String ATTACK_COMMAND = "winshock";

    @Parameter(names = "-signature_length", description = "Length of the signature in the CertificateVerify protocol message")
    Integer signatureLength;

    @Parameter(names = "-signature", description = "Signature value in the CertificateVerify protocol message", converter = BigIntegerConverter.class, required = true)
    BigInteger signature;

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
