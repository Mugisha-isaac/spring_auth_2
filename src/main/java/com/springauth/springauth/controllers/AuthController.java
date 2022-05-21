package com.springauth.springauth.controllers;

import com.springauth.springauth.model.ERole;
import com.springauth.springauth.model.Role;
import com.springauth.springauth.model.User;
import com.springauth.springauth.payload.request.LoginRequest;
import com.springauth.springauth.payload.request.SignupRequest;
import com.springauth.springauth.payload.response.JwtResponse;
import com.springauth.springauth.payload.response.MessageResponse;
import com.springauth.springauth.repository.RoleRepository;
import com.springauth.springauth.repository.UserRepository;
import com.springauth.springauth.security.jwt.JwtUtils;
import com.springauth.springauth.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    UserRepository userRepository;
    @Autowired
    RoleRepository roleRepository;
    @Autowired
    PasswordEncoder encoder;
    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest){
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),loginRequest.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generatedJwtToken(authentication);
        UserDetailsImpl  userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item->item.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(jwt,userDetails.getId(),userDetails.getUsername(),userDetails.getEmail(), roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest ){
        if(userRepository.existByUsername(signupRequest.getUsername())){
            return ResponseEntity.badRequest().body(new MessageResponse("Error: username is already taken"));
        }

        if(userRepository.existByEmail(signupRequest.getEmail())){
            return ResponseEntity.badRequest().body("Error: Email is already in use");
        }

        User user = new User(signupRequest.getUsername(),signupRequest.getEmail(),encoder.encode(signupRequest.getPassword()));
        Set<String> strRoles = signupRequest.getRole();
        Set<Optional<Role>> roles = new HashSet<>();

        if(strRoles == null){
            Optional<Role> userRole = Optional.ofNullable(roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found")));
            roles.add(userRole);
        }
        else{
            strRoles.forEach(role->{
                switch (role){
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(()->new RuntimeException("Error: Role is not found"));
                        roles.add(Optional.ofNullable(adminRole));

                        break;

                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(()->new RuntimeException("Error: Role is not found"));

                        roles.add(Optional.ofNullable(modRole));
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);
       return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }
}
