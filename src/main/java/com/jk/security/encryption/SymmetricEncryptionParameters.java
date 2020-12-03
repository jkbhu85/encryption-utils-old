package com.jk.security.encryption;

import javax.crypto.SecretKey;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Parameters to use for symmetric encryption.
 * 
 * @author Jitendra Kumar
 */
@AllArgsConstructor
@Getter
public class SymmetricEncryptionParameters {
	private String algorithm;
	private String method;
	private SecretKey secretKey;
	private byte[] iv;
	private int numberOfTagBits;
}
