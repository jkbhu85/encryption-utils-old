package com.jk.security.encryption;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class AsymmetricEncryptionService implements EncryptionService {

	private final AsymmetricEncryptionParameters encryptionParameters;

	public AsymmetricEncryptionService(AsymmetricEncryptionParameters encryptionParameters) {
		this.encryptionParameters = encryptionParameters;
	}

	private byte[] doOperation(final int mode, final byte[] data) {
		try {
			final Cipher cipher = Cipher.getInstance(encryptionParameters.getMethod(), "BC");
			if (mode == Cipher.ENCRYPT_MODE) {
				cipher.init(Cipher.ENCRYPT_MODE, encryptionParameters.getPublicKey());
			}
			else {
				cipher.init(Cipher.DECRYPT_MODE, encryptionParameters.getPrivateKey());
			}
			final int blockSize = cipher.getBlockSize();

			final ByteArrayOutputStream out = new ByteArrayOutputStream(data.length);
			int start = 0;
			while (start < data.length) {
				int end;
				if (start + blockSize > data.length) {
					end = data.length;
				}
				else {
					end = start + blockSize;
				}
				final byte[] encrypted = cipher.doFinal(Arrays.copyOfRange(data, start, end));
				out.write(encrypted);

				start += blockSize;
			}
			final byte[] output = out.toByteArray();
			out.close();
			return output;
		}
		catch (IllegalBlockSizeException | BadPaddingException | IOException | NoSuchAlgorithmException
				| NoSuchPaddingException | InvalidKeyException | NoSuchProviderException e) {
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
