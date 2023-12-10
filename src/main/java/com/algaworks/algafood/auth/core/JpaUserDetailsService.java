package com.algaworks.algafood.auth.core;

import com.algaworks.algafood.auth.domain.model.Usuario;
import com.algaworks.algafood.auth.domain.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Serviço responsável pela autenticação de um usuário
 *
 * @author Idevaldo Neto <idevbn@gmail.com>
 */
@Service
public class JpaUserDetailsService implements UserDetailsService {

    private final UsuarioRepository repository;

    @Autowired
    public JpaUserDetailsService(final UsuarioRepository repository) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(final String username)
            throws UsernameNotFoundException {

        final Usuario usuario = this.repository.findByEmail(username)
                .orElseThrow(() ->
                        new UsernameNotFoundException("Usuário não encontrado com email informado")
                );

        final AuthUser authUser = new AuthUser(usuario);

        return authUser;
    }

}
