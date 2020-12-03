package com.jk.security;

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;

public class AppUtils {

	public static String fileName(String fileNameTemplate, String placeholder) {
		if (placeholder == null) placeholder = "";
		return fileNameTemplate.replace("{}", placeholder);
	}

	public static int computeDecryptionBlockSize(int keySize, String algorithm) {
		Objects.requireNonNull(algorithm);

		int blockSize;
		switch (algorithm) {
		case "RSA":
			blockSize = keySize / 8;
			break;
		default:
			throw new IllegalArgumentException("Algorithm is not supported. Value: " + algorithm);
		}
		return blockSize;
	}

	public static int computeEncryptionBlockSize(int keySize, String algorithm) {
		Objects.requireNonNull(algorithm);

		int blockSize;
		switch (algorithm) {
		case "RSA":
			blockSize = (keySize / 8) - 42;
			break;
		default:
			throw new IllegalArgumentException("Algorithm is not supported. Value: " + algorithm);
		}
		return blockSize;
	}
	
	public static String getDateTime() {
		return new SimpleDateFormat(Consts.DATA_TIME_FORMAT).format(new Date());
	}
	
	public static void printAsBlock(String title, String message) {
		System.out.println("--------------------------------------------------------------------------------");
		System.out.println(title);
		System.out.println("--------------------------------------------------------------------------------");
		System.out.println(message);
		System.out.println("--------------------------------------------------------------------------------\n");
	}
	
	@SafeVarargs
	public static <T> List<T> asUnmodifiableList(T ... args) {
		return Collections.unmodifiableList(Arrays.asList(args));
	}

}
