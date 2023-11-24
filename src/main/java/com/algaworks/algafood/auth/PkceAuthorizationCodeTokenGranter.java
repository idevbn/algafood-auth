package com.algaworks.algafood.auth;

import org.apache.commons.codec.binary.Base64;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PkceAuthorizationCodeTokenGranter extends AuthorizationCodeTokenGranter {

    public PkceAuthorizationCodeTokenGranter(
            final AuthorizationServerTokenServices tokenServices,
            final AuthorizationCodeServices authorizationCodeServices,
            final ClientDetailsService clientDetailsService,
            final OAuth2RequestFactory requestFactory
    ) {
        super(tokenServices, authorizationCodeServices, clientDetailsService, requestFactory);
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(final ClientDetails client,
                                                           final TokenRequest tokenRequest) {
        final OAuth2Authentication authentication = super.getOAuth2Authentication(client, tokenRequest);
        final OAuth2Request request = authentication.getOAuth2Request();

        final String codeChallenge = request.getRequestParameters().get("code_challenge");
        final String codeChallengeMethod = request.getRequestParameters().get("code_challenge_method");
        final String codeVerifier = request.getRequestParameters().get("code_verifier");

        if (codeChallenge != null || codeChallengeMethod != null) {
            if (codeVerifier == null) {
                throw new InvalidGrantException("Code verifier expected.");
            }

            if (!validateCodeVerifier(codeVerifier, codeChallenge, codeChallengeMethod)) {
                throw new InvalidGrantException(codeVerifier + " does not match expected code verifier.");
            }
        }

        return authentication;
    }

    private boolean validateCodeVerifier(final String codeVerifier,
                                         final String codeChallenge,
                                         final String codeChallengeMethod) {

        String generatedCodeChallenge;

        if ("plain".equalsIgnoreCase(codeChallengeMethod)) {
            generatedCodeChallenge = codeVerifier;
        } else if ("s256".equalsIgnoreCase(codeChallengeMethod)) {
            generatedCodeChallenge = generateHashSha256(codeVerifier);
        } else {
            throw new InvalidGrantException(codeChallengeMethod + " is not a valid challenge method.");
        }

        return generatedCodeChallenge.equals(codeChallenge);
    }

    private static String generateHashSha256(final String plainText) {
        try {
            final MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

            final byte[] hash = messageDigest.digest(Utf8.encode(plainText));

            return Base64.encodeBase64URLSafeString(hash);
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

}
