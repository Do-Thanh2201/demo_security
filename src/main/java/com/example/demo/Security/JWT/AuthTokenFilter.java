package com.example.demo.Security.JWT;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


/*
*   OncePerRequestFilter makes a single execution for each request to our API.
*   It provides a doFilterInternal() method
*       that we will implement parsing & validating JWT,
*           loading User details (using UserDetailsService),
*           checking Authorizaion (using UsernamePasswordAuthenticationToken).
*
* */
@Component
public class AuthTokenFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private UserDetailsService userDetailsService;
    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            /*
            * Get JWT from the Authorization header (by removing Bearer prefix)
            * Call Method parseJwt
            * */
            String jwt = parseJwt(request);

            /* Check the request has JWT, validate it? */
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                /* parse username from it: Tach lay user tu Jwt */
                String username = jwtUtils.getUserNameFromJwtToken(jwt);
                /*=======
                * 1. UserDetails la 1 Interface,
                *    userDetails se goi cac Method cua Interface UserDetails duoc Override o Class UserDetailsImpl
                *    Bao gom:  getId(), getUsername(), getEmail(), getPassword(),
                *              getAuthorities(), isAccountNonExpired(), isAccountNonLocked(),
                *              isCredentialsNonExpired(), isEnabled(), equals()
                *   (The hien da hinh runtime)
                * 2. UserDetailsService la 1 Interface,
                *   userDetailsService se goi cac Method cua Interface UserDetailsService
                *   Duoc Override o Class UserDetailsServiceImpl
                *   Bao gom: loadUserByUsername()
                *   (The hien da hinh runtime)
                * 3. userDetailsService.loadUserByUsername(username) se goi den Method build trong Class UserDetailsImpl
                *    De tao ra mot Authentication object
                *=======*/
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                /*=====
                *  1. UsernamePasswordAuthenticationToken gets {username, password} from login Request,
                *      AuthenticationManager will use it to authenticate a login account.
                *  2. AuthenticationManager has a DaoAuthenticationProvider (with help of UserDetailsService & PasswordEncoder)
                *      to validate UsernamePasswordAuthenticationToken object.
                *      If successful, AuthenticationManager returns a fully populated Authentication object
                *      (including granted authorities).
                *=====*/

                /*
                * Spring Security hold the principal information of each authenticated user
                * in a ThreadLocal – represented as an Authentication object.
                * In order to: construct and set this Authentication object
                * */
                // construct this Authentication object
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                // set this Authentication object
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                /*  Set the current UserDetails in SecurityContext using setAuthentication(authentication) method.*/
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        /*
        * Spring Security filter chain will validate and return error code automatically
        * CHo phép request duoc di tiep (vuot qua filter nay)
        * */
        filterChain.doFilter(request, response);
    }

    /*
    * Parse Jwt from the Authorization header
    * */
    private String parseJwt(HttpServletRequest request) {
        /*
        *   request bat dau bang Authorization
        * */
        String headerAuth = request.getHeader("Authorization");

        /*
        * Jwt bắt đầu sau "Bearer "
         * */
        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7, headerAuth.length());
        }
        return null;
    }
}
