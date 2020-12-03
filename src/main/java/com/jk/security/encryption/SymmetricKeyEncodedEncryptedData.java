package com.jk.security.encryption;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class SymmetricKeyEncodedEncryptedData {
	private String encodedEncryptedKey;
	private String encodedEncryptedIv;
}
