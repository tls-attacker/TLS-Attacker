/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Config;

import com.beust.jcommander.Parameters;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
@Parameters(commandDescription = "Executes all TestVectors which caused an Exception while Fuzzing. This is useful for Debugging purposes.")
public class ExecuteFaultyConfig extends FuzzerGeneralConfig {

}
