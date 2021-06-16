package com.realizer.jwt.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.filter.CorsFilter;

import lombok.AllArgsConstructor;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	private final CorsFilter corsFilter;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		/** 
		 * JWT 구성조건
		 */
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Session 사용 안함.
		.and()
		.addFilter(corsFilter)  // Controller에 @CrossOrigin을 거는 건 인증이 없는 경우, 시큐리티 필터에 등록해야 인증
		.formLogin().disable() // FORMLOGIN 안씀
		.httpBasic().disable() // HTTP로그인방식 안씀
		.authorizeRequests()
		.antMatchers("/api/v1/user/**")
		.access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER') or hasRole('ROLE_USER')")
		.antMatchers("/api/v1/manager/**")
		.access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
		.antMatchers("/api/v1/admin/**")
		.access("hasRole('ROLE_ADMIN')")
		.anyRequest().permitAll();
	}

}
