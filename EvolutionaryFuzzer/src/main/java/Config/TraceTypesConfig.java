/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
@Parameters(commandDescription = "Analyzes a Folder with TestVector Files and opens a GraphWindow with a report of the different TraceTypes")
public class TraceTypesConfig {
    @Parameter(names = "-output", description = "The Folder with the TestVectors which should be analyzed")
    String traceTypesFolder = "data/uniqueFlows";

    public String getTraceTypesFolder() {
	return traceTypesFolder;
    }

    public void setTraceTypesFolder(String traceTypesFolder) {
	this.traceTypesFolder = traceTypesFolder;
    }

}
