/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.compressor.compression;

import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import java.util.Arrays;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public class DeflateCompression extends CompressionAlgorithm {

    private final static int MAX_COMPRESSION_TEXT_LENGTH = 0x4400;
    private final static int MAX_PLAIN_TEXT_LENGTH = 0x4000;
    private Boolean secondPacketFlagCompression;
    private Boolean secondPacketFlagDecompression;

    public DeflateCompression() {
        super(CompressionMethod.DEFLATE);
        secondPacketFlagCompression = false;
        secondPacketFlagDecompression = false;
    }

    public byte[] compress(byte[] data) {

        byte[] input = data;
        byte[] output = new byte[MAX_COMPRESSION_TEXT_LENGTH];
        Deflater compressor = new Deflater();

        compressor.setInput(input, 0, input.length);

        int compressedDataLength = compressor.deflate(output, 0, MAX_COMPRESSION_TEXT_LENGTH, compressor.SYNC_FLUSH);

        byte[] realOutput = new byte[compressedDataLength];
        System.arraycopy(output, 0, realOutput, 0, compressedDataLength);

        byte[] veryRealOutput;

        if (secondPacketFlagCompression) {
            veryRealOutput = Arrays.copyOfRange(realOutput, 2, realOutput.length);
        } else {
            veryRealOutput = Arrays.copyOfRange(realOutput, 0, realOutput.length);
            secondPacketFlagCompression = true;
        }

        return veryRealOutput;
    }

    public byte[] decompress(byte[] data) {

        byte[] input = data;
        byte[] output = new byte[MAX_PLAIN_TEXT_LENGTH];
        byte[] veryRealInput;

        if (secondPacketFlagDecompression) {
            veryRealInput = new byte[input.length + 2];
            veryRealInput[0] = (byte) 0x78;
            veryRealInput[1] = (byte) 0x9C;
            System.arraycopy(input, 0, veryRealInput, 2, input.length);

        } else {
            veryRealInput = new byte[input.length];
            System.arraycopy(input, 0, veryRealInput, 0, input.length);
            secondPacketFlagDecompression = true;
        }

        Inflater decompressor = new Inflater();
        decompressor.setInput(veryRealInput, 0, veryRealInput.length);
        int decompressedDataLength = 0;

        try {
            decompressedDataLength = decompressor.inflate(output, 0, MAX_PLAIN_TEXT_LENGTH);
        } catch (Exception e) {
            LOGGER.debug("Couldn't decompress the data");
            LOGGER.trace(e);
        }

        byte[] realOutput = new byte[decompressedDataLength];
        System.arraycopy(output, 0, realOutput, 0, decompressedDataLength);

        return realOutput;
    }

}
