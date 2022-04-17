package com.example.api.appuser;

import com.example.api.registration.token.ConfirmationToken;
import com.example.api.registration.token.ConfirmationTokenService;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@AllArgsConstructor
public class AppUserService implements UserDetailsService {

    private final AppUserRepository appUserRepository;
    private final ConfirmationTokenService confirmationTokenService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final static String USER_NOT_FOUND_MSG =
            "user with email %s not found";
    @Override
    public UserDetails loadUserByUsername(String email)
            throws UsernameNotFoundException {

        return appUserRepository.findByEmail(email)
                .orElseThrow(() ->
                        new UsernameNotFoundException(
                                String.format(USER_NOT_FOUND_MSG,email)));
    }

    public String signUPUser (AppUser appUser){
        boolean userExist = appUserRepository.
                findByEmail(appUser.getEmail()).
                isPresent();
        if (userExist){
            throw new IllegalStateException("email is taken");
        }
        String encodePassword = bCryptPasswordEncoder.
                encode(appUser.getPassword());
        appUser.setPassword(encodePassword);

        appUserRepository.save(appUser);

        String token = UUID.randomUUID().toString();
        ConfirmationToken confirmationToken = new ConfirmationToken(
                token,
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(15),
                appUser
        );

        confirmationTokenService.saveConfirmationToken(
                confirmationToken);

        return token;
    }
    public int enableAppUser(String email) {
        return appUserRepository.enableAppUser(email);
    }
}
