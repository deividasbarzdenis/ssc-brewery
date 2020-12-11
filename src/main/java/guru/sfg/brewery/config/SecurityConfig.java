package guru.sfg.brewery.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
        /*new BCryptPasswordEncoder()*/
        /*new StandardPasswordEncoder();*/
        /*new LdapShaPasswordEncoder();*/
    }
   /* @Bean //NoOp implementation
    PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }*/

    @Override
    protected void configure(HttpSecurity http) throws Exception {
            http
                    .authorizeRequests(authorize -> {
                        authorize
                                .antMatchers("/", "/webjars/**", "/login", "resources/**").permitAll()
                                .antMatchers("/beers/find", "/beers*").permitAll()
                                .antMatchers(HttpMethod.GET, "/api/v1/beer/**").permitAll()
                                .antMatchers(HttpMethod.GET, "/api/v1/beerUpc/{upc}").permitAll();
                    })
                    .authorizeRequests()
                    .anyRequest().authenticated()
                    .and()
                    .formLogin().and()
                    .httpBasic();
    }

/**
   *In Memory authentication:
* */

    @Override //we using fluent api
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("spring")
                .password("{bcrypt}$2a$10$zV8sSZYcTVc1bGhMCOFWXusS5jksYOCQlpgb7bu5Bl0N8y/P5s6cy")
                .roles("ADMIN")
                .and()
                .withUser("user")
                .password("{sha256}b247950e58a5dd58eff90de9f22eac5743d62835ddd79cc2a86de2169aade6d1faceccae259150ba")
                .roles("USER")
                .and()
                .withUser("scott")
                .password("{ldap}{SSHA}3e1lgOfi8aBg6vjQhM4/I0ryxvvy7/xWlCvOwA==")
                .roles("CUSTOMER");
    }

/*    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails admin = User.withDefaultPasswordEncoder()
                .username("spring")
                .password("guru")
                .roles("ADMIN")
                .build();
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(admin, user);
    }*/
}
