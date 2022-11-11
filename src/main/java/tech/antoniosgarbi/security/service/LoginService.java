package tech.antoniosgarbi.security.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import tech.antoniosgarbi.security.dto.LoginDTO;
import tech.antoniosgarbi.security.dto.RefreshDTO;
import tech.antoniosgarbi.security.dto.TokenDTO;

@Service
public class LoginService {
    private final TokenService tokenService;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;

    public LoginService(TokenService tokenService, AuthenticationManager authenticationManager, UserDetailsService userDetailsService) {
        this.tokenService = tokenService;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
    }

    public TokenDTO login(LoginDTO loginDTO) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginDTO.getUsername(), loginDTO.getSenha())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String accessToken = tokenService.gerarToken(userDetails);
        String refreshToken = tokenService.gerarRefreshToken(userDetails);

        return new TokenDTO(accessToken, refreshToken);
    }

    public TokenDTO refresh(RefreshDTO refreshDTO) {
        String token = refreshDTO.getRefreshToken();

        if(tokenService.validarRefreshToken(token)) {
            String username = tokenService.getUsernameFromToken(token);

            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            String accessToken = tokenService.gerarToken(userDetails);
            String refreshToken = tokenService.gerarRefreshToken(userDetails);

            return new TokenDTO(accessToken, refreshToken);
        } else {
            throw new BadCredentialsException("Refresh token expirado, faça login novamente");
        }
    }
}
