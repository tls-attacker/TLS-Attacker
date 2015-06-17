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
package de.rub.nds.tlsattacker.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

/**
 * Source: http://javatechniques.com/blog/faster-deep-copies-of-java-objects
 * Utility for making deep copies (vs. clone()'s shallow copies) of objects.
 * Objects are first serialized and then deserialized. Error checking is fairly
 * minimal in this implementation. If an object is encountered that cannot be
 * serialized (or that references an object that cannot be serialized) an error
 * is printed to System.err and null is returned. Depending on your specific
 * application, it might make more sense to have copy(...) re-throw the
 * exception. A later version of this class includes some minor optimizations.
 * TODO: analyze problems with Serializable
 */
public class UnoptimizedDeepCopy {

    /**
     * Returns a copy of the object, or null if the object cannot be serialized.
     */
    public static Object copy(Object orig) {
	Object obj = null;

	try {

	    // Write the object out to a byte array
	    ByteArrayOutputStream bos = new ByteArrayOutputStream();
	    ObjectOutputStream out = new ObjectOutputStream(bos);

	    out.writeObject(orig);
	    out.flush();
	    out.close();

	    // Make an input stream from the byte array and read
	    // a copy of the object back in.
	    ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bos.toByteArray()));

	    obj = in.readObject();
	} catch (IOException | ClassNotFoundException e) {
	    e.printStackTrace();
	}

	return obj;
    }
}
