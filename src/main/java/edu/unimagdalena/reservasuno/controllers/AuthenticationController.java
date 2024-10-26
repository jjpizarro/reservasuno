package edu.unimagdalena.reservasuno.controllers;

import edu.unimagdalena.reservasuno.controllers.dto.JwtResponse;
import edu.unimagdalena.reservasuno.controllers.dto.LoginRequest;
import edu.unimagdalena.reservasuno.controllers.dto.SignupRequest;
import edu.unimagdalena.reservasuno.entities.User;
import edu.unimagdalena.reservasuno.repositories.UserRepository;
import edu.unimagdalena.reservasuno.security.jwt.JwtUtil;
import edu.unimagdalena.reservasuno.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {
    @Autowired PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    UserRepository userRepository;
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest){
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.username(),
                        loginRequest.password())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwtToken= jwtUtil.generateJwtToken(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl)authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(role -> role.getAuthority()).collect(Collectors.toList());
        return ResponseEntity.ok(new JwtResponse(jwtToken, "Bearer", userDetails.getUsername(), roles));
    }
    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody SignupRequest sRequest){
        User user = new User(null,
                sRequest.username(),
                passwordEncoder.encode(sRequest.password()),
                sRequest.email(),
                new HashSet<>());
        Set<String> roles = sRequest.roles();
        User newUser = userRepository.save(user);
        return ResponseEntity.ok(newUser);
    }
}
