/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.config.analyzer;

import tlsattacker.fuzzer.config.analyzer.RuleConfig;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import javax.xml.bind.annotation.XmlRootElement;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

/**
 * A configuration class for the ProtocolVersionRule
 * 
 * @author ic0ns
 */
@XmlRootElement
public class ProtocolVersionRuleConfig extends RuleConfig {
    private boolean allowSSL2 = false;
    private boolean allowSSL3 = true;
    private boolean allowTLS10 = true;
    private boolean allowTLS11 = true;
    private boolean allowTLS12 = true;
    private boolean allowDTLS10 = true;
    private boolean allowDTLS12 = true;
    private boolean logOnWrongFieldSizes = true;

    public ProtocolVersionRuleConfig() {
        super("faulty_version/");
    }

    public boolean isLogOnWrongFieldSizes() {
        return logOnWrongFieldSizes;
    }

    public void setLogOnWrongFieldSizes(boolean logOnWrongFieldSizes) {
        this.logOnWrongFieldSizes = logOnWrongFieldSizes;
    }

    public boolean isAllowSSL2() {
	return allowSSL2;
    }

    public boolean isAllowDTLS10() {
	return allowDTLS10;
    }

    public void setAllowDTLS10(boolean allowDTLS10) {
	this.allowDTLS10 = allowDTLS10;
    }

    public boolean isAllowDTLS12() {
	return allowDTLS12;
    }

    public void setAllowDTLS12(boolean allowDTLS12) {
	this.allowDTLS12 = allowDTLS12;
    }

    public void setAllowSSL2(boolean allowSSL2) {
	this.allowSSL2 = allowSSL2;
    }

    public boolean isAllowSSL3() {
	return allowSSL3;
    }

    public void setAllowSSL3(boolean allowSSL3) {
	this.allowSSL3 = allowSSL3;
    }

    public boolean isAllowTLS10() {
	return allowTLS10;
    }

    public void setAllowTLS10(boolean allowTLS10) {
	this.allowTLS10 = allowTLS10;
    }

    public boolean isAllowTLS11() {
	return allowTLS11;
    }

    public void setAllowTLS11(boolean allowTLS11) {
	this.allowTLS11 = allowTLS11;
    }

    public boolean isAllowTLS12() {
	return allowTLS12;
    }

    public void setAllowTLS12(boolean allowTLS12) {
	this.allowTLS12 = allowTLS12;
    }

    public boolean isAllowedVersion(ProtocolVersion version) {
	if (version == ProtocolVersion.SSL2) {
	    return allowSSL2;
	} else if (version == ProtocolVersion.SSL3) {
	    return allowSSL3;
	} else if (version == ProtocolVersion.TLS10) {
	    return allowTLS10;
	} else if (version == ProtocolVersion.TLS11) {
	    return allowTLS11;
	} else if (version == ProtocolVersion.TLS12) {
	    return allowTLS12;
	} else if (version == ProtocolVersion.DTLS10) {
	    return allowDTLS10;
	} else if (version == ProtocolVersion.DTLS12) {
	    return allowDTLS12;
	} else {
	    throw new UnsupportedOperationException();
	}
    }
}
