/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable.mlong;

import de.rub.nds.tlsattacker.modifiablevariable.FileConfigurationException;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.modifiablevariable.integer.IntegerModificationFactory;
import de.rub.nds.tlsattacker.util.RandomHelper;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

/**
 * @author
 */
final public class LongModificationFactory {

    private static final int MODIFICATION_COUNT = 5;

    private static final int MAX_MODIFICATION_VALUE = 32000;

    private static List<VariableModification<Long>> modificationsFromFile;

    private LongModificationFactory() {
    }

    public static LongAddModification add(final String summand) {
        return add(new Long(summand));
    }

    public static LongAddModification add(final Long summand) {
        return new LongAddModification(summand);
    }

    public static VariableModification<Long> sub(final String subtrahend) {
        return sub(new Long(subtrahend));
    }

    public static VariableModification<Long> sub(final Long subtrahend) {
        return new LongSubtractModification(subtrahend);
    }

    public static VariableModification<Long> xor(final String xor) {
        return xor(new Long(xor));
    }

    public static VariableModification<Long> xor(final Long xor) {
        return new LongXorModification(xor);
    }

    public static VariableModification<Long> explicitValue(final String value) {
        return explicitValue(new Long(value));
    }

    public static VariableModification<Long> explicitValue(final Long value) {
        return new LongExplicitValueModification(value);
    }

    public static VariableModification<Long> explicitValueFromFile(int value) {
        List<VariableModification<Long>> modifications = modificationsFromFile();
        int pos = value % modifications.size();
        return modifications.get(pos);
    }

    public static List<VariableModification<Long>> modificationsFromFile() {
        try {
            if (modificationsFromFile == null) {
                modificationsFromFile = new LinkedList<>();
                ClassLoader classLoader = IntegerModificationFactory.class.getClassLoader();
                File file = new File(classLoader.getResource(IntegerModificationFactory.FILE_NAME).getFile());
                BufferedReader br = new BufferedReader(new FileReader(file));
                String line;
                while ((line = br.readLine()) != null) {
                    String value = line.trim().split(" ")[0];
                    modificationsFromFile.add(explicitValue(value));
                }
            }
            return modificationsFromFile;
        } catch (IOException ex) {
            throw new FileConfigurationException("Modifiable variable file name could not have been found.", ex);
        }
    }

    public static VariableModification<Long> createRandomModification() {
        Random random = RandomHelper.getRandom();
        int r = random.nextInt(MODIFICATION_COUNT);
        long modification = random.nextInt(MAX_MODIFICATION_VALUE);
        VariableModification<Long> vm = null;
        switch (r) {
            case 0:
                vm = new LongAddModification(modification);
                return vm;
            case 1:
                vm = new LongSubtractModification(modification);
                return vm;
            case 2:
                vm = new LongXorModification(modification);
                return vm;
            case 3:
                vm = new LongExplicitValueModification(modification);
                return vm;
            case 4:
                vm = explicitValueFromFile(random.nextInt(MAX_MODIFICATION_VALUE));
                return vm;
        }
        return vm;
    }

}
