package de.rub.nds.tlsattacker.attacks.impl;

public class FisherExactTest {
	public static double getLog2PValue(int inputAOutput1, int inputBOutput1, int inputAoutput2, int inputBOutput2) {
		int a = inputAOutput1;
		int b = inputBOutput1;
		int c = inputAoutput2;
		int d = inputBOutput2;
		int n = a + b + c + d;
		double nominator = log2Factorial(a+b) + log2Factorial(c+d) + log2Factorial(a+c) + log2Factorial(b+d);
		double denominator = log2Factorial(a) + log2Factorial(b) + log2Factorial(c) + log2Factorial(d) + log2Factorial(n);
		return nominator - denominator;
	}
	
	public static double log2Factorial(int k) {
		double res = 0;
		for (int i = 2; i < k; i++) {
			res += log2(i);
		}
		return res;
	}

	private static double log2(int i) {
		return Math.log(i) / Math.log(2);
	}
}
