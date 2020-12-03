package com.jk.security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Consts {

	public static final String SECURITY_PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

	public static final String ASYMMETRIC_ENCRYPTION_ALGORITHM = "RSA";
	public static final String ASYMMETRIC_ENCRYPTION_METHOD = "RSA/None/OAEPWITHSHA-384ANDMGF1PADDING";
	
	public static final String PROPERTY_SECRET_KEY = "encryption.symmetric.encoded-encrypted-secret-key";
	public static final String PROPERTY_IV = "encryption.symmetric.encoded-encrypted-iv";

	public static final String SYMMETRIC_ENCRYPTION_ALGORITHM = "AES";
	public static final String SYMMETRIC_ENCRYPTION_METHOD = "AES/GCM/NoPadding";
	public static final int SYMMETRIC_ENCRYPTION_GCM_TAG_BITS = 128;
	public static final int SYMMETRIC_ENCRYPTION_NUMBER_OF_VI_BYTES = 12;
	
	public static final String SYMMETRIC_KEY_FILE_NAME = "key.symmetric.{}.properties";
	public static final String PUBLIC_KEY_FILE_NAME = "key.{}.public.txt";
	public static final String PRIVATE_KEY_FILE_NAME = "key.{}.private.txt";
	
	public static final String DATA_TIME_FORMAT = "yyyy-MM-dd-HH-mm-ss";

}
