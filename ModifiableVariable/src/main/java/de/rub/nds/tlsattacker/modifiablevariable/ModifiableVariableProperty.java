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
package de.rub.nds.tlsattacker.modifiablevariable;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation interface for modifiable variables.
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface ModifiableVariableProperty {

    public enum Type {

	LENGTH,
	COUNT,
	PADDING,
	/** variable presenting one or more (array of) TLS constants */
	TLS_CONSTANT,
	SIGNATURE,
	CIPHERTEXT,
	HMAC,
	PUBLIC_KEY,
	PRIVATE_KEY,
	KEY_MATERIAL,
	CERTIFICATE,
	/** plain protocol message, always in a decrypted state */
	PLAIN_PROTOCOL_MESSAGE,
	COOKIE,
	NONE
    }

    public enum Format {

	ASN1,
	PKCS1,
	NONE
    }

    Type type() default Type.NONE;

    Format format() default Format.NONE;

}
