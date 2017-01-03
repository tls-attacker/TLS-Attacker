/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.config.analyzer;

import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * A configuration class for the ProtocolVersionRule
 * 
 * @author ic0ns
 */
@XmlRootElement
public class ProtocolVersionRuleConfig extends RuleConfig {

    /**
     * If the rule should blacklist ssl2
     */
    private boolean allowSSL2 = false;

    /**
     * If the rule should blacklist ssl3
     */
    private boolean allowSSL3 = true;

    /**
     * If the rule should blacklist tls 1.0
     */
    private boolean allowTLS10 = true;

    /**
     * If the rule should blacklist tls 1.1
     */
    private boolean allowTLS11 = true;

    /**
     * If the rule should blacklist tls 1.2
     */
    private boolean allowTLS12 = true;

    /**
     * If the rule should blacklist dtls 1.0
     */
    private boolean allowDTLS10 = true;

    /**
     * If the rule should blacklist dtls 1.2
     */
    private boolean allowDTLS12 = true;

    /**
     *
     */
    public ProtocolVersionRuleConfig() {
        super("faulty_version/");
    }

    /**
     * 
     * @return
     */
    public boolean isAllowSSL2() {
        return allowSSL2;
    }

    /**
     * 
     * @return
     */
    public boolean isAllowDTLS10() {
        return allowDTLS10;
    }

    /**
     * 
     * @param allowDTLS10
     */
    public void setAllowDTLS10(boolean allowDTLS10) {
        this.allowDTLS10 = allowDTLS10;
    }

    /**
     * 
     * @return
     */
    public boolean isAllowDTLS12() {
        return allowDTLS12;
    }

    /**
     * 
     * @param allowDTLS12
     */
    public void setAllowDTLS12(boolean allowDTLS12) {
        this.allowDTLS12 = allowDTLS12;
    }

    /**
     * 
     * @param allowSSL2
     */
    public void setAllowSSL2(boolean allowSSL2) {
        this.allowSSL2 = allowSSL2;
    }

    /**
     * 
     * @return
     */
    public boolean isAllowSSL3() {
        return allowSSL3;
    }

    /**
     * 
     * @param allowSSL3
     */
    public void setAllowSSL3(boolean allowSSL3) {
        this.allowSSL3 = allowSSL3;
    }

    /**
     * 
     * @return
     */
    public boolean isAllowTLS10() {
        return allowTLS10;
    }

    /**
     * 
     * @param allowTLS10
     */
    public void setAllowTLS10(boolean allowTLS10) {
        this.allowTLS10 = allowTLS10;
    }

    /**
     * 
     * @return
     */
    public boolean isAllowTLS11() {
        return allowTLS11;
    }

    /**
     * 
     * @param allowTLS11
     */
    public void setAllowTLS11(boolean allowTLS11) {
        this.allowTLS11 = allowTLS11;
    }

    /**
     * 
     * @return
     */
    public boolean isAllowTLS12() {
        return allowTLS12;
    }

    /**
     * 
     * @param allowTLS12
     */
    public void setAllowTLS12(boolean allowTLS12) {
        this.allowTLS12 = allowTLS12;
    }

    /**
     * 
     * @param version
     * @return
     */
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
