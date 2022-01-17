package com.example.demo.Controller;
import com.example.demo.Service.AuthService;
import com.example.demo.payload.Request.LoginRequest;
import com.example.demo.payload.Request.SignupRequest;
import com.example.demo.payload.Response.JwtResponse;
import com.example.demo.payload.Response.MessageResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import javax.validation.Valid;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")

/*======================================================================================================================
*                   This controller provides APIs for register and login actions
* =====================================================================================================================*/
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /*==================================================================================================================
    *
    * /api/auth/signin:
    *                   Authenticate { username, pasword }
    *                   Update SecurityContext using Authentication object
    *                   Generate JWT
    *                   Get UserDetails from Authentication object
    *                   Response contains JWT and UserDetails data
    *
    * =================================================================================================================*/
    @PostMapping("/signin")
    public ResponseEntity<JwtResponse> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        return ResponseEntity.ok(authService.authenticateLogin(loginRequest));
    }

    /*==================================================================================================================
     *
     * /api/auth/signup:
     *                   Check existing username/email
     *                   Create new User (with ROLE_USER if not specifying role)
     *                   Save User to database using UserRepository
     *
     * =================================================================================================================*/
    @PostMapping("/signup")
    public ResponseEntity<MessageResponse> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        return authService.registerUser(signUpRequest);
    }

}
