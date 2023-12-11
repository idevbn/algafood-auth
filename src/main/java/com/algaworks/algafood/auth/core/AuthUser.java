package com.algaworks.algafood.auth.core;

import com.algaworks.algafood.auth.domain.model.Usuario;
import lombok.Getter;
import org.springframework.security.core.userdetails.User;

import java.util.Collections;

/**
 * Classe que recebe os dados do usuário a ser autenticado
 *
 * @author Idevaldo Neto <idevbn@gmail.com>
 */
@Getter
public class AuthUser extends User {

    private Long userId;
    private String fullName;

    public AuthUser(final Usuario usuario) {
        super(usuario.getEmail(), usuario.getSenha(), Collections.emptyList());

        this.userId = usuario.getId();
        this.fullName = usuario.getNome();
    }

}
