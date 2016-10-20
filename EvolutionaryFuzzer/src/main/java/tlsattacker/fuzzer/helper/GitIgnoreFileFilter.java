/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.helper;

import java.io.File;
import java.io.FilenameFilter;

/**
 * A FileFilter that ignores .gitignore files
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class GitIgnoreFileFilter implements FilenameFilter {

    @Override
    public boolean accept(File dir, String name) {
	if (name.equals(".gitignore")) {
	    return false;
	}
	return true;
    }

}
