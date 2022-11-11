package tech.antoniosgarbi.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tech.antoniosgarbi.security.dto.LoginDTO;
import tech.antoniosgarbi.security.dto.RefreshDTO;
import tech.antoniosgarbi.security.dto.TokenDTO;
import tech.antoniosgarbi.security.service.LoginService;

@RestController
@RequestMapping("/auth")
public class LoginController {
    private final LoginService loginService;


    public LoginController(LoginService loginService) {
        this.loginService = loginService;
    }

    @PostMapping("/login")
    public ResponseEntity<TokenDTO> login(@RequestBody LoginDTO loginDTO) {
        return ResponseEntity.ok(this.loginService.login(loginDTO));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenDTO> refresh(@RequestBody RefreshDTO refreshDTO) {
        return ResponseEntity.ok(this.loginService.refresh(refreshDTO));
    }
}
