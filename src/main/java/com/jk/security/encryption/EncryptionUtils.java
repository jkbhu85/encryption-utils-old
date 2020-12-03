package com.jk.security.encryption;

import java.security.KeyPair;

import com.jk.security.Consts;

public class EncryptionUtils {
	public static AsymmetricEncryptionParameters getDefaultParams(KeyPair keyPair) {
		return new AsymmetricEncryptionParameters(Consts.ASYMMETRIC_ENCRYPTION_ALGORITHM,
				Consts.ASYMMETRIC_ENCRYPTION_METHOD, keyPair.getPublic(),
				keyPair.getPrivate());
	}

	public static SymmetricEncryptionParameters getDefaultParameters(SymmetricKey symmetricKey) {
		return new SymmetricEncryptionParameters(Consts.SYMMETRIC_ENCRYPTION_ALGORITHM,
				Consts.SYMMETRIC_ENCRYPTION_METHOD,
				symmetricKey.getSecretKey(), symmetricKey.getIv(), Consts.SYMMETRIC_ENCRYPTION_GCM_TAG_BITS);
	}
}
