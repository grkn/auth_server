package com.to.go.fit.config;

import com.to.go.fit.security.TgfAuthenticationManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
@EnableMethodSecurity
public class SecurityConfig {
    private final TgfAuthenticationManager tgfAuthenticationManager;

    public SecurityConfig(TgfAuthenticationManager tgfAuthenticationManager) {
        this.tgfAuthenticationManager = tgfAuthenticationManager;
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        // You can change default settings here. Ex: url of token endpoint
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public BearerTokenAuthenticationFilter bearerTokenAuthenticationFilter() {
        BearerTokenAuthenticationFilter bearerTokenAuthenticationFilter = new BearerTokenAuthenticationFilter(tgfAuthenticationManager);
        bearerTokenAuthenticationFilter.setBearerTokenResolver(request -> {
            if (request.getHeader("Authorization") != null) {
                return request.getHeader("Authorization").contains("Bearer ") ? request.getHeader("Authorization").replace("Bearer ", "") : null;
            }

            return null;
        });
        return bearerTokenAuthenticationFilter;
    }

    @Bean
    public UserDetailsService userDetailsService(BCryptPasswordEncoder encoder) {
        UserDetails user = User.builder()
                .authorities("write")
                .username("user")
                .password(encoder.encode("password"))
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http, UserDetailsService userDetailsService) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        http.with(authorizationServerConfigurer, Customizer.withDefaults());
        return http.anonymous(AbstractHttpConfigurer::disable).csrf(AbstractHttpConfigurer::disable)
                .authenticationManager(tgfAuthenticationManager)
                .userDetailsService(userDetailsService)
                .authorizeHttpRequests(registry -> registry
                        .requestMatchers("/forgot-password", "/change-password").permitAll()
                        .requestMatchers("/js/**", "/css/**", "/images/**").permitAll()
                        .anyRequest().permitAll())
                .formLogin(httpSecurityFormLoginConfigurer -> httpSecurityFormLoginConfigurer
                        .usernameParameter("username")
                        .passwordParameter("password")
                        .loginPage("/login.html")
                        .loginProcessingUrl("/client/authenticate")
                        .failureForwardUrl("/login?error=true")
                        .successForwardUrl("/index.html")
                        .defaultSuccessUrl("/index.html")
                        .permitAll())
                .build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http.csrf(AbstractHttpConfigurer::disable)
                .addFilter(bearerTokenAuthenticationFilter())
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()).build();
    }
}
