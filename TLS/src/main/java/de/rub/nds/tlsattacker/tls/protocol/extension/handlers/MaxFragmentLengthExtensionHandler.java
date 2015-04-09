/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
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
package de.rub.nds.tlsattacker.tls.protocol.extension.handlers;

import de.rub.nds.tlsattacker.tls.protocol.extension.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.tls.protocol.extension.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.extension.messages.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class MaxFragmentLengthExtensionHandler extends ExtensionHandler<MaxFragmentLengthExtensionMessage> {

    private static MaxFragmentLengthExtensionHandler instance;

    /**
     * Max fragment length
     */
    public static final int MAX_FRAGMENT_LENGTH = 1;

    private MaxFragmentLengthExtensionHandler() {

    }

    public static MaxFragmentLengthExtensionHandler getInstance() {
	if (instance == null) {
	    instance = new MaxFragmentLengthExtensionHandler();
	}
	return instance;
    }

    @Override
    public void initializeClientHelloExtension(MaxFragmentLengthExtensionMessage extension) {
	byte[] maxFragmentLength = { extension.getMaxFragmentLengthConfig().getValue() };

	extension.setExtensionType(ExtensionType.MAX_FRAGMENT_LENGTH.getValue());
	extension.setMaxFragmentLength(maxFragmentLength);

	extension.setExtensionLength(extension.getMaxFragmentLength().getValue().length);

	byte[] result = ArrayConverter.concatenate(extension.getExtensionType().getValue(),
		ArrayConverter.intToBytes(extension.getExtensionLength().getValue(), ExtensionByteLength.EXTENSIONS),
		extension.getMaxFragmentLength().getValue());

	extension.setExtensionBytes(result);
    }

    @Override
    public int parseExtension(byte[] message, int pointer) {
	if (extensionMessage == null) {
	    extensionMessage = new MaxFragmentLengthExtensionMessage();
	}
	MaxFragmentLengthExtensionMessage mflExtension = (MaxFragmentLengthExtensionMessage) extensionMessage;
	int nextPointer = pointer + ExtensionByteLength.TYPE;
	byte[] extensionType = Arrays.copyOfRange(message, pointer, nextPointer);
	mflExtension.setExtensionType(extensionType);

	pointer = nextPointer;
	nextPointer = pointer + ExtensionByteLength.EXTENSIONS;
	int extensionLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, pointer, nextPointer));
	mflExtension.setExtensionLength(extensionLength);

	pointer = nextPointer;
	byte[] fragmentLength = { message[pointer] };
	mflExtension.setMaxFragmentLength(fragmentLength);

	byte[] result = ArrayConverter
		.concatenate(mflExtension.getExtensionType().getValue(), ArrayConverter.intToBytes(mflExtension
			.getExtensionLength().getValue(), ExtensionByteLength.EXTENSIONS), mflExtension
			.getMaxFragmentLength().getValue());
	mflExtension.setExtensionBytes(result);

	return pointer + 1;
    }

}
