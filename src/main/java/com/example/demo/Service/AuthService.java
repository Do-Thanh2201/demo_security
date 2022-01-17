package com.example.demo.Service;


import com.example.demo.Models.ERole;
import com.example.demo.Models.Role;
import com.example.demo.Models.User;
import com.example.demo.Repository.RoleRepository;
import com.example.demo.Repository.UserRepository;
import com.example.demo.Security.JWT.JwtUtils;
import com.example.demo.Security.Service.UserDetailsImpl;
import com.example.demo.payload.Request.LoginRequest;
import com.example.demo.payload.Request.SignupRequest;
import com.example.demo.payload.Response.JwtResponse;
import com.example.demo.payload.Response.MessageResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class AuthService {


    AuthenticationManager authenticationManager;
    UserRepository userRepository;
    RoleRepository roleRepository;
    PasswordEncoder encoder;
    JwtUtils jwtUtils;

    public AuthService(AuthenticationManager authenticationManager,
                          UserRepository userRepository,
                          RoleRepository roleRepository,
                          PasswordEncoder encoder, JwtUtils jwtUtils) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.encoder = encoder;
        this.jwtUtils = jwtUtils;
    }

    public JwtResponse authenticateLogin (LoginRequest loginRequest)
    {
        /*====
         *       Authenticate { username, pasword }
         * 1.    UsernamePasswordAuthenticationToken gets {username, password} from login Request,
         *       AuthenticationManager will use it to authenticate a login account.
         * 2.    AuthenticationManager has a DaoAuthenticationProvider (with help of UserDetailsService & PasswordEncoder)
         *       to validate UsernamePasswordAuthenticationToken object.
         *       If successful, AuthenticationManager returns a fully populated Authentication object (including granted authorities).
         *
         * ===*/

        /*
         *   Spring Security hold the principal information of each authenticated user
         * in a ThreadLocal – represented as an Authentication object.
         *   In order to construct and set this Authentication object,
         * we need to use the same approach Spring Security typically uses to build the object on a standard authentication.
         * */

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        /*  //Dong code tren tuong duong voi:
        // Contruct this Authentication object
        UsernamePasswordAuthenticationToken authReq
                = new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword());
        // set this Authentication object
        Authentication auth = authenticationManager.authenticate(authReq);
        * */


        /*====
         *       Update SecurityContext using Authentication object
         *====*/
        SecurityContextHolder.getContext().setAuthentication(authentication);
        /*====
         *       Generate JWT
         *=====*/
        String jwt = jwtUtils.generateJwtToken(authentication);
        /*====
         *      Get UserDetails from Authentication object
         *=====*/
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        /*====
         *      Nhan cac Roles cua User trong UserDetails
         *=====*/
        List<String> roles =
                userDetails.getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList());
        /*====
         *      Response contains JWT and UserDetails data
         *=====*/
        return new JwtResponse(
                        jwt,
                        userDetails.getId(),
                        userDetails.getUsername(),
                        userDetails.getEmail(),
                        roles);
    }

    public ResponseEntity<MessageResponse> registerUser(SignupRequest signUpRequest) {
        /*====
         *      Check existing email
         *=====*/
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        /*====
         *       Check existing email
         *=====*/

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }
        /*====
         *      Create new User (with ROLE_USER if not specifying role)
         *=====*/

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));
        /*====
         *
         *=====*/
        Set<String> strRoles = signUpRequest.getRole();
        /*====
         *
         *=====*/
        Set<Role> roles = new HashSet<>();
        /*====
         *
         *=====*/
        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        }
        else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin" -> {
                        Role adminRole =
                                roleRepository.findByName(ERole.ROLE_ADMIN)
                                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);
                    }
                    case "mod" -> {
                        Role modRole =
                                roleRepository.findByName(ERole.ROLE_MODERATOR)
                                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);
                    }
                    default -> {
                        Role userRole =
                                roleRepository.findByName(ERole.ROLE_USER)
                                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                    }
                }
            });
        }
        /*====
         *      Save User to database using UserRepository
         *=====*/
        user.setRoles(roles);
        userRepository.save(user);
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }
}
