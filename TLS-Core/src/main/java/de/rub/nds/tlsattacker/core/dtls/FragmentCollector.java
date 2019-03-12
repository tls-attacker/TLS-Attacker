/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.dtls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Comparator;
import java.util.TreeSet;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.serializer.DtlsHandshakeMessageFragmentSerializer;

/**
 * Collector used for storing and assembling DTLS fragments.
 * It provides support for disorderly fragment insertion and fragment overlap.
 */
public class FragmentCollector {

    protected static final Logger LOGGER = LogManager.getLogger(FragmentCollector.class.getName());

    private Integer messageLength;

    private Integer messageSeq;

    private Byte type;

    // a variable which configures the collector whether to store unfitting fragments 
    private boolean onlyFitting;
    
    // a set which keeps fragments sorted firstly by their offset, secondly by their length
    private final TreeSet<DtlsHandshakeMessageFragment> fragmentData;

    
    public FragmentCollector(boolean onlyFitting) {
    	fragmentData = new TreeSet<>(new Comparator<DtlsHandshakeMessageFragment>() {
            @Override
            public int compare(DtlsHandshakeMessageFragment o1, DtlsHandshakeMessageFragment o2) {
            	int comp = o1.getFragmentOffset().getValue().compareTo(o2.getFragmentOffset().getValue());
            	if (comp == 0) {
            		// if two fragments start at the same offset, we sort by length from longest to shortest
            		comp = o2.getFragmentLength().getValue().compareTo(o1.getFragmentLength().getValue());
            	}
                return comp;
            }
        });
    	this.onlyFitting = onlyFitting;
    }
    
    public FragmentCollector() {
        this(false);
    }
    
    

    /**
     * Tries to insert a fragment in the collection. Fragments already contained will not be added.
     * 
     * <p>
	 * Note: If onlyFitting is true, it only adds messages which "fit" in the collection, 
	 * that is, which share the same type, length and message sequence with the first 
	 * element inserted in the collection. 
	 * </p>
     * 
     * @return true if the fragment was added or false if it wasn't.
     */
    public boolean addFragment(DtlsHandshakeMessageFragment fragment) {
        boolean isFitting = parseType(fragment);
        isFitting &= parseMessageSeq(fragment);
        isFitting &= parseLength(fragment);
        
        if (!fragmentData.contains(fragment) && (isFitting || !onlyFitting)) {
            fragmentData.add(fragment);
            return true;
        } else {
        	return false;
        }
    }

    private boolean parseType(DtlsHandshakeMessageFragment fragment) {
        Byte fType = fragment.getType().getValue();
        if (type == null) {
            type = fType;
        } else {
            if (!type.equals(fType)) {
                LOGGER.warn("Found an unffiting fragment! Type before:" + type + " inserted fragment type:" + fType);
                return false;
            }
        }
        return true;
    }

    private boolean parseMessageSeq(DtlsHandshakeMessageFragment fragment) {
        Integer fMessageSeq = fragment.getMessageSeq().getValue();
        if (messageSeq == null) {
            messageSeq = fMessageSeq;
        } else {
            if (!messageSeq.equals(fMessageSeq)) {
                LOGGER.warn("Found an unffiting fragment! Message seq before:" + messageSeq
                        + " inserted fragment message seq:" + fMessageSeq);
                return false;
            }
        }
        return true;
    }

    private boolean parseLength(DtlsHandshakeMessageFragment fragment) {
        Integer fLength = fragment.getLength().getValue();
        if (messageLength == null) {
            messageLength = fLength;
        } else {
            if (!messageLength.equals(fLength)) {
                LOGGER.warn("Found an unffiting fragment! Message length before:" + messageLength
                        + " inserted fragment length:" + fLength);
                return false;
            }
        }
        return true;
    }

    /**
     * Assembles collected messages into a combined fragment. 
     * Note that missing bytes are replaced by 0.
     */
    public DtlsHandshakeMessageFragment getCombinedFragment() {
        if (!isMessageComplete()) {
            LOGGER.warn("Returning incompletely received message! Missing pieces are replaced by 0 in content.");
        }
        if (type == null) {
            throw new WorkflowExecutionException("DtlsFragmentedMessage does not have type!");
        }

        DtlsHandshakeMessageFragment message = new DtlsHandshakeMessageFragment();
        message.setType(type);
        message.setLength(messageLength);
        message.setMessageSeq(messageSeq);
        message.setFragmentOffset(0);
        message.setFragmentLength(messageLength);
        message.setContent(getCombinedContent());
        DtlsHandshakeMessageFragmentSerializer serializer = new DtlsHandshakeMessageFragmentSerializer(
                message, null);
        message.setCompleteResultingMessage(serializer.serialize());
        return message;
    }

    /* Combines the content in collected fragments, filling the gaps with 0s.
     * Note: the implementation relies on the sorted nature of {@link fragmentData}.
     */
    private byte[] getCombinedContent() {
        try {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            int currentOffset = 0;
            for (DtlsHandshakeMessageFragment fragment : fragmentData) {
            	Integer fragOffset = fragment.getFragmentOffset().getValue();
            	Integer fragLength = fragment.getFragmentLength().getValue();
            	// fragment contains bytes already received
            	if (currentOffset > fragOffset+fragLength) {
            		continue;
            	} else {
            		// fragment starts at an offset we haven't yet arrived at
            		if (fragOffset > currentOffset) {
            			LOGGER.warn("Missing bytes between offsets " + fragOffset + 
            					" and " + currentOffset + ". Filling gap with 0s.");
            			stream.write(new byte[fragOffset-currentOffset]);
            			currentOffset = fragOffset;
            		}
            		// the place to start copying
            		int offsetDiff = currentOffset - fragOffset;
            		stream.write(fragment.getContent().getValue(), offsetDiff, fragLength-offsetDiff);
            		currentOffset += (fragLength - offsetDiff);
            	}
            }
            byte[] array = stream.toByteArray();
            if (!messageLength.equals(array.length)) {
                LOGGER.warn("Assembled message length is different than expected message length. "
                        + "Truncating/filling with 0s.");
                array = Arrays.copyOf(array, messageLength);
            }
            return array;
        } catch (IOException e) {
            LOGGER.error("Failure merging content, return 0 byte array");
            return new byte[messageLength];
        }
    }

    /**
     * Assembles the message, serializes it and returns the resulting byte array.
     */
    public byte[] getCombinedFragmentAsByteArray() {
        DtlsHandshakeMessageFragment combinedFragment = getCombinedFragment();
        DtlsHandshakeMessageFragmentSerializer serializer = new DtlsHandshakeMessageFragmentSerializer(
                combinedFragment, null);
        return serializer.serialize();
    }

    /**
     * Returns true if enough messages have been received to assemble the message.
     * Otherwise returns false. 
     */
    public boolean isMessageComplete() {
        if (messageLength == null) {
            return false;
        } else {
        	int currentOffset = 0;
            for (DtlsHandshakeMessageFragment fragment : fragmentData) {
            	if (currentOffset > fragment.getFragmentOffset().getValue() 
            				+ fragment.getFragmentLength().getValue()) {
            		continue;
            	} else {
	            	if (fragment.getFragmentOffset().getValue() > currentOffset) {
	            		return false;
	            	} else {
	            		currentOffset = fragment.getFragmentOffset().getValue() 
	            				+ fragment.getFragmentLength().getValue();
	            	}
            	}
            	if (currentOffset >= messageLength) {
            		break;
            	}
            }
            
            if (currentOffset > messageLength) {
            	LOGGER.warn("Assembled message is longer than message length");
            }
            
            return currentOffset >= messageLength;
        }
    }

}
