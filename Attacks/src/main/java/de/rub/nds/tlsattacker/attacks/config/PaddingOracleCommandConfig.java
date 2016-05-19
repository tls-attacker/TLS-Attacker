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
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import java.util.LinkedList;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class PaddingOracleCommandConfig extends ClientCommandConfig {

    public static final String ATTACK_COMMAND = "padding_oracle";

    @Parameter(names = "-block_size", description = "Block size of the to be used block cipher")
    Integer blockSize = 16;

    public PaddingOracleCommandConfig() {
	cipherSuites = new LinkedList<>();
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256);
    }

    public Integer getBlockSize() {
	return blockSize;
    }

    public void setBlockSize(Integer blockSize) {
	this.blockSize = blockSize;
    }

}
