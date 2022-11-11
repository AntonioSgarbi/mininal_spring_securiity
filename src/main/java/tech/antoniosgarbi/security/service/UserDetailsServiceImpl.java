package tech.antoniosgarbi.security.service;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import tech.antoniosgarbi.security.model.Usuario;
import tech.antoniosgarbi.security.repository.UsuarioRepository;

import java.util.List;
import java.util.Optional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UsuarioRepository usuarioRepository;

    public UserDetailsServiceImpl(UsuarioRepository usuarioRepository) {
        this.usuarioRepository = usuarioRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Usuario usuario = buscarUsuarioPeloUsername(username);

        String authorityString = "ROLE_" + usuario.getRole();

        GrantedAuthority authority = new SimpleGrantedAuthority(authorityString);

        return new User(usuario.getUsername(), usuario.getSenha(), List.of(authority));
    }

    private Usuario buscarUsuarioPeloUsername(String username) {
        Optional<Usuario> optional = this.usuarioRepository.findByUsername(username);

        if(optional.isEmpty()) {
            throw new UsernameNotFoundException("Usuario não foi encontrado");
        }

        return optional.get();

    }
}
