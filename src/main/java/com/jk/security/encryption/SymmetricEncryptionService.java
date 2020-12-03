package com.jk.security.encryption;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import com.jk.security.Consts;

public class SymmetricEncryptionService implements EncryptionService {

	private final SymmetricEncryptionParameters encryptionParameters;

	public SymmetricEncryptionService(SymmetricEncryptionParameters symmetricEncryptionParameters) {
		this.encryptionParameters = symmetricEncryptionParameters;
	}

	private byte[] doOperation(final int mode, final byte[] input) {
		try {
			final Cipher cipher = Cipher.getInstance(encryptionParameters.getMethod(), Consts.SECURITY_PROVIDER);
			cipher.init(mode, encryptionParameters.getSecretKey(),
					new IvParameterSpec(encryptionParameters.getIv()));
			return cipher.doFinal(input);
		}
		catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
				| NoSuchProviderException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public byte[] encrypt(byte[] input) {
		return doOperation(Cipher.ENCRYPT_MODE, input);
	}

	@Override
	public byte[] decrypt(byte[] input) {
		return doOperation(Cipher.DECRYPT_MODE, input);
	}

}
