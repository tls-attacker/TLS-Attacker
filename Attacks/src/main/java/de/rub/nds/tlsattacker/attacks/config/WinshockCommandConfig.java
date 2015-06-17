/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
