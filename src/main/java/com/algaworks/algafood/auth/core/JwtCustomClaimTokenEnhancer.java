package com.algaworks.algafood.auth.core;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.util.HashMap;
import java.util.Map;

public class JwtCustomClaimTokenEnhancer implements TokenEnhancer {

    @Override
    public OAuth2AccessToken enhance(final OAuth2AccessToken accessToken,
                                     final OAuth2Authentication authentication) {

        if (authentication.getPrincipal() instanceof AuthUser) {

            final AuthUser authUser = (AuthUser) authentication.getPrincipal();

            final Map<String, Object> info = new HashMap<>();

            info.put("nome_completo", authUser.getFullName());
            info.put("user_id", authUser.getUserId());

            DefaultOAuth2AccessToken defaultAccessToken = (DefaultOAuth2AccessToken) accessToken;
            defaultAccessToken.setAdditionalInformation(info);
        }

        return accessToken;
    }

}
