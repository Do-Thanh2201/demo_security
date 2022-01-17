package com.example.demo;


import com.example.demo.Security.JWT.AuthEntryPointJwt;
import com.example.demo.Security.JWT.AuthTokenFilter;
import com.example.demo.Security.Service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;



/*
* WebSecurityConfigurerAdapter is the crux of our security implementation.
* (Phan quan trong de trien khai bao mat)
* It provides HttpSecurity configurations to configure cors, csrf, session management, rules for protected resources.
* We can also extend and customize the default configuration that contains the elements below.
* */

@Configuration // Can thiet

/*===========================================================================================
*   @EnableWebSecurity
*   Allows Spring to find and automatically apply the class to the global Web Security.
* ===========================================================================================*/
@EnableWebSecurity // Can thiet

/*============================================================================================
*   @EnableGlobalMethodSecurity
*
*   securedEnabled = true enables @Secured annotation.
*   jsr250Enabled = true enables @RolesAllowed annotation.
*   prePostEnabled = true enables @PreAuthorize, @PostAuthorize, @PreFilter, @PostFilter annotations.
*   (Cac anotations tren duoc su dung trong file controler cho cac api vi du: TestController,...)
* ============================================================================================*/
@EnableGlobalMethodSecurity(
        // securedEnabled = true,
        // jsr250Enabled = true,
        prePostEnabled = true)

public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    // Can thiet
    final UserDetailsServiceImpl userDetailsService;
    // Nem ra mot ngoai le de xu ly
    private final AuthEntryPointJwt unauthorizedHandler;
    @Autowired
    public WebSecurityConfig(UserDetailsServiceImpl userDetailsService, AuthEntryPointJwt unauthorizedHandler) {
        this.userDetailsService = userDetailsService;
        this.unauthorizedHandler = unauthorizedHandler;
    }


    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }


    /*=================================================================================================
    *  @Override configure() Method
    * It tells Spring Security how we configure CORS and CSRF,
    * when we want to require all users to be authenticated or not,
    * which filter (AuthTokenFilter) and when we want it to work (filter before UsernamePasswordAuthenticationFilter),
    * which Exception Handler is chosen (AuthEntryPointJwt).
    *
    * Spring Security will load User details to perform authentication & authorization.
    *       So it has UserDetailsService interface that we need to implement.
    * The implementation of UserDetailsService will be used for configuring
    *       DaoAuthenticationProvider by AuthenticationManagerBuilder.userDetailsService() method.
    * We also need a PasswordEncoder for the DaoAuthenticationProvider. If we don’t specify, it will use plain text.
    *
    * ===============================================================================================*/



    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
/*
         ToDo configure authentication manager
         O day ta dang ky Authentication Provider la dang User-Password
*/
        /*
        * the authenticationManagerBuilder.userDetailsService function call will initiate the DaoAuthenticationProvider instance
        * using our implementation of the UserDetailsService interface and register it in the authentication manager.
        * */
        authenticationManagerBuilder
                .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    /*
    *   AuthenticationManager mac dinh la disable nen can tao bean de enable no len
    * */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        /*
        *       Use the bcrypt password-hashing algorithm.
        * */
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
/*
         ToDo configure web security
*/

        // Enable CORS and disable CSRF
        http = http.cors().and().csrf().disable()

        // Set unauthorized requests exception handler
        .exceptionHandling()
                .authenticationEntryPoint(unauthorizedHandler)
                .and()

        // Set session management to stateless
        .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and();

        // Set permissions on endpoints
        http.authorizeRequests()
                // Our public endpoints. Cac Request dang nay thi khong can xac thuc
                .antMatchers("/api/auth/**").permitAll()
                .antMatchers("/api/test/**").permitAll()
                /*
                // Our private endpoints ...
                .antMatchers("/api/admin/user/**").hasRole(Role.USER_ADMIN)
                .antMatchers("/api/author/**").hasRole(Role.AUTHOR_ADMIN)
                .antMatchers("/api/book/**").hasRole(Role.BOOK_ADMIN)
*/
                // Các request còn lại đều cần được authenticated
                .anyRequest().authenticated();

        // Add JWT token filter
        /*
        * ưu tiên Sử dụng bộ lọc authenticationJwtTokenFilter() trước
        * Nếu không sử dụng phương pháp xác thực: UsernamePasswordAuthenticationFilter.class
        * */
        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}
