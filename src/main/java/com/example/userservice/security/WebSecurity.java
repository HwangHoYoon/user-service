package com.example.userservice.security;

import jakarta.validation.constraints.NotNull;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class WebSecurity{
    @Bean
    public WebSecurityCustomizer ignoringCustomizer() {
        return (web) -> web.ignoring().requestMatchers(PathRequest.toH2Console());
    }
    @Bean
    public SecurityFilterChain securityFilterChain(final @NotNull HttpSecurity http) throws Exception {
        http.httpBasic(HttpBasicConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .authorizeHttpRequests(authorize ->
                                authorize
                                        .requestMatchers("/**")
                                        .permitAll().anyRequest().authenticated()

                )
                .headers(headers -> {
                    headers.frameOptions(withDefaults());
                })
        ;
        return http.build();
    }
}
