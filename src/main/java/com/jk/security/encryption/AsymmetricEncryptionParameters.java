package com.jk.security.encryption;

import java.security.PrivateKey;
import java.security.PublicKey;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Parameters to use for asymmetric encryption.
 * 
 * @author Jitendra Kumar
 */
@AllArgsConstructor
@Getter
public class AsymmetricEncryptionParameters {
	private String algorithm;
	private String method;
	private PublicKey publicKey;
	private PrivateKey privateKey;
}
