package com.jk.security.encryption;

public interface EncryptionService {

	byte[] encrypt(byte[] input);
	
	byte[] decrypt(byte[] input);
}
