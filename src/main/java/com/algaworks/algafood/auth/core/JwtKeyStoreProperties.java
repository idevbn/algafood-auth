package com.algaworks.algafood.auth;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotBlank;

/**
 * Classe com os parâmetros da keystore
 * para chave jwt assimétrica.
 *
 * @author Idevaldo Neto <idevbn@gmail.com>
 */
@Getter
@Setter
@Validated
@Component
@ConfigurationProperties("algafood.jwt.keystore")
public class JwtKeyStoreProperties {

    @NotBlank
    private String path;
    @NotBlank
    private String password;
    @NotBlank
    private String keyPairAlias;

}
