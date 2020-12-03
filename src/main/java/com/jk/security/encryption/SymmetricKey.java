package com.jk.security.encryption;

import javax.crypto.SecretKey;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class SymmetricKey {
	private SecretKey secretKey;
	private byte[] iv;

}
