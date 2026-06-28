package com.msisc.bis.security;

import com.misc.bis.security.NakisaClientIdAndSecretCredentialsProviderFactory;
import org.junit.Test;

public class SHA256Test {

    @Test
    public void shouldGenerateSha256HashedString() throws Exception {
        String sha256 = NakisaClientIdAndSecretCredentialsProviderFactory.sha256("O2iJM92ND8SwHeLuIXz5WHeg5KAEIvuu");
        System.out.println(sha256);
    }

}
