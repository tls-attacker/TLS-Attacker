/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.validators.PositiveInteger;
import de.rub.nds.tlsattacker.tls.config.validators.PercentageValidator;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class CalibrationConfig extends FuzzerGeneralConfig {
    @Parameter(names = "-gain", required = false, description = "Increase Timeout by this factor")
    private double gain = 1.2;
    @Parameter(names = "-Limit", required = false, description = "Do not look for timeouts greater than this Limit", validateWith = PercentageValidator.class)
    private int timeoutLimit = 4000;

    public double getGain() {
	return gain;
    }

    public void setGain(double gain) {
	this.gain = gain;
    }

    public int getTimeoutLimit() {
	return timeoutLimit;
    }

    public void setTimeoutLimit(int timeoutLimit) {
	this.timeoutLimit = timeoutLimit;
    }

}
