package com.example.demo.Security;

import com.example.demo.auth.ApplicationUserService;
import com.example.demo.jwt.JVerifierFilter;
import com.example.demo.jwt.JWTConfig;
import com.example.demo.jwt.JWTUserFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;


import javax.crypto.SecretKey;

import static com.example.demo.Security.AppUserPermission.COURSE_WRITE;
import static com.example.demo.Security.AppUserPermission.STUDENT_WRITE;
import static com.example.demo.Security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;

    private final JWTConfig jwtConfig;
    private final SecretKey secretKey;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService, JWTConfig jwtConfig, SecretKey secretKey) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JWTUserFilter(authenticationManager(), jwtConfig, secretKey))
                .addFilterAfter(new JVerifierFilter(jwtConfig, secretKey), JWTUserFilter.class)
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll() //Specify routes t0 exclude from basic auth
                .antMatchers("/api/**").hasAnyRole(ADMIN.name(), STUDENT.name())
                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAnyAuthority(STUDENT_WRITE.getPermissions(), COURSE_WRITE.name()) // Only users with student read or course read permissions
                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAnyAuthority(STUDENT_WRITE.getPermissions(), COURSE_WRITE.name())
                // .antMatchers(HttpMethod.POST, "/management/api/**").hasAnyAuthority(STUDENT_WRITE.getPermissions(), COURSE_WRITE.name())
                // .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMIN_TRAINEE.name()) // only admin members can reach this endpoint;
                .anyRequest()//all other requests made to this server
                .authenticated() ;// should be authenticated

    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(daoAuthenticationProvider());
    } // Override default configure method that takes AuthenticationManagerBuilder as parameter

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);

        return provider;
    }
}
