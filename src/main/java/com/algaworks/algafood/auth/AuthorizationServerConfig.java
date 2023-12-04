package com.algaworks.algafood.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.security.KeyPair;
import java.util.Arrays;
import java.util.List;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final JwtKeyStoreProperties jwtKeyStoreProperties;

    @Autowired
    public AuthorizationServerConfig(final PasswordEncoder passwordEncoder,
                                     final AuthenticationManager authenticationManager,
                                     final UserDetailsService userDetailsService,
                                     final JwtKeyStoreProperties jwtKeyStoreProperties) {
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.jwtKeyStoreProperties = jwtKeyStoreProperties;
    }

    @Override
    public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {
        clients
                .inMemory()
                .withClient("algafood-web")
                .secret(this.passwordEncoder.encode("web123"))
                .authorizedGrantTypes("password", "refresh_token")
                .scopes("write", "read")
                .accessTokenValiditySeconds(60 * 60 * 6) // 6 horas (padrão é 12 horas)
                .refreshTokenValiditySeconds(15 * 60 * 60) // refresh_token de 15 dias

                .and()
                .withClient("foodanalytics")
//                .secret(this.passwordEncoder.encode("food123"))
                .secret(this.passwordEncoder.encode(""))
                .authorizedGrantTypes("authorization_code")
                .scopes("write", "read")
//                    .redirectUris("http://aplicacao-cliente")
                .redirectUris("http://localhost:8082")

                .and()
                .withClient("faturamento")
                .secret(this.passwordEncoder.encode("faturamento123"))
                .authorizedGrantTypes("client_credentials")
                .scopes("read")

                .and()
                .withClient("checktoken")
                .secret(this.passwordEncoder.encode("check123"));
    }

    @Override
    public void configure(final AuthorizationServerSecurityConfigurer security) throws Exception {

        /**
         * security.checkTokenAccess("isAuthenticated()");
         * Com o permitAll() não é necessário autenticar o usuário
         */
        security.checkTokenAccess("permitAll()")
                .tokenKeyAccess("permitAll()")
                .allowFormAuthenticationForClients();
    }

    @Override
    public void configure(final AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .authenticationManager(this.authenticationManager)
                .userDetailsService(this.userDetailsService)
                .accessTokenConverter(this.jwtAccessTokenConverter())
                .approvalStore(this.approvalStore(endpoints.getTokenStore()))
                .tokenGranter(this.tokenGranter(endpoints));
        /**
         * Com essa configuração, o mesmo refresh_token não gera outros access_token
         *  o default é true
         */
//                .reuseRefreshTokens(false);
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        final JwtAccessTokenConverter jwtAccessTokenConverter
                = new JwtAccessTokenConverter();

//        jwtAccessTokenConverter.setSigningKey("aa27b16ae5be4cdf90d9c37a35f9298a");

        final String path = this.jwtKeyStoreProperties.getPath();
        final String password = this.jwtKeyStoreProperties.getPassword();
        final String pairAlias = this.jwtKeyStoreProperties.getKeyPairAlias();

        final ClassPathResource jksResource = new ClassPathResource(path);

        final KeyStoreKeyFactory keyStoreKeyFactory
                = new KeyStoreKeyFactory(jksResource, password.toCharArray());
        final KeyPair keyPair = keyStoreKeyFactory.getKeyPair(pairAlias);

        jwtAccessTokenConverter.setKeyPair(keyPair);

        return jwtAccessTokenConverter;
    }

    private ApprovalStore approvalStore(final TokenStore tokenStore) {
        final TokenApprovalStore approvalStore = new TokenApprovalStore();

        approvalStore.setTokenStore(tokenStore);

        return approvalStore;
    }

    private TokenGranter tokenGranter(final AuthorizationServerEndpointsConfigurer endpoints) {
        final PkceAuthorizationCodeTokenGranter pkceAuthorizationCodeTokenGranter
                = new PkceAuthorizationCodeTokenGranter(
                endpoints.getTokenServices(),
                endpoints.getAuthorizationCodeServices(),
                endpoints.getClientDetailsService(),
                endpoints.getOAuth2RequestFactory()
        );

        final List<TokenGranter> granters = Arrays.asList(
                pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter()
        );

        return new CompositeTokenGranter(granters);
    }

}
