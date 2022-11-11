package tech.antoniosgarbi.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.antoniosgarbi.security.model.Usuario;

import java.util.Optional;

public interface UsuarioRepository extends JpaRepository<Usuario, Long> {
    Optional<Usuario> findByUsername(String email);
}
