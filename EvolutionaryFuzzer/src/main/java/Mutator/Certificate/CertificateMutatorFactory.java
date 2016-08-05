/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Mutator.Certificate;

import Config.EvolutionaryFuzzerConfig;
import Exceptions.IllegalCertificateMutatorException;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateMutatorFactory {
    public static CertificateMutator getCertificateMutator(EvolutionaryFuzzerConfig config)
	    throws IllegalCertificateMutatorException {
	switch (config.getCertMutator()) {
	    case "fixed":
		return new FixedCertificateMutator();
	    default:
		throw new IllegalCertificateMutatorException("Illegal Value for Certificate Mutator:"
			+ config.getMutator());
	}
    }
}
