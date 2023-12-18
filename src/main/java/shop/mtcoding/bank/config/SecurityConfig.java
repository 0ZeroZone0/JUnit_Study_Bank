package shop.mtcoding.bank.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import shop.mtcoding.bank.domain.user.UserEnum;

@Configuration
public class SecurityConfig {
    private final Logger log = LoggerFactory.getLogger(getClass());

    @Bean // IoC 컨테이너에 BCryptPasswordEncoder() 객체가 등록됨.
    public BCryptPasswordEncoder passwordEncoder() {
        log.debug("디버그 : BCryptPasswordEncoder 빈 등록됨.");
        return new BCryptPasswordEncoder();
    }

    // JWT 필터 등록이 필요함.

    // JWT 서버를 만들 예정!! Session 사용안함.
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        log.debug("디버그 : filterChain 빈 등록됨");
        http
                // iframe 허용안함.
                .headers((header) -> header.frameOptions(
                        HeadersConfigurer.FrameOptionsConfig::sameOrigin))
                // enable이면 post맨 작동안함
                .csrf(AbstractHttpConfigurer::disable)
                // jSessionId를 서버쪽에서 관리안하겠다는 뜻!!
                .cors(corsConfigurer -> corsConfigurer.configurationSource(configurationSource()))
                .sessionManagement(
                        (sessionManagement) -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .formLogin((f) -> f.disable())
                .httpBasic((h) -> h.disable())
                .authorizeHttpRequests(authenticated -> authenticated.requestMatchers("/api/s/**").authenticated())
                .authorizeHttpRequests(registry -> registry.requestMatchers("/api/admin/**")
                        .hasRole("" + UserEnum.ADMIN)
                        .anyRequest()
                        .permitAll());

        return http.build();
    }

    public CorsConfigurationSource configurationSource() {
        log.debug("디버그 : configurationSource cors 설정이 SecurityFilterChain에 등록됨");
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*"); // GET, POST, PUT, DELETE (Javascript 요청 허용)
        configuration.addAllowedOriginPattern("*"); // 모든 IP 주소 허용 (프론트 앤드 IP만 허용 react)
        configuration.setAllowCredentials(true); // 클라이언트에서 쿠키 요청 허용

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}