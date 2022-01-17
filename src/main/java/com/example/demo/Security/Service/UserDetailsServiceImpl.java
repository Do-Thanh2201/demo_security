package com.example.demo.Security.Service;

import com.example.demo.Models.User;
import com.example.demo.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
/*
* UserDetailsService interface has a method to load User by username and returns a UserDetails object
* that Spring Security can use for authentication and validation.
*
* */

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    UserRepository userRepository;
    /*==================================================================================================================
    *   Getting UserDetails object
    * =================================================================================================================*/
    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    // So sanh xem user co ton tai khong
        User user = userRepository.findByUsername(username)
                .orElseThrow(
                        () -> new UsernameNotFoundException("User Not Found with username: " + username));
    //
        return UserDetailsImpl.build(user);
    }
}
