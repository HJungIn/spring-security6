package com.example.springsecurity6.config;

import com.example.springsecurity6.UserDetailsService;
import com.example.springsecurity6.common.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.ErrorResponse;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.io.PrintWriter;
import java.util.Arrays;
import java.util.Collections;

@EnableWebSecurity
@Configuration
@Slf4j
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final UserDetailsService userDetailsService;
    private final AuthenticationConfiguration authenticationConfiguration;

    /**
     * 이 메서드는 정적 자원에 대해 보안을 적용하지 않도록 설정한다.
     * 정적 자원은 보통 HTML, CSS, JavaScript, 이미지 파일 등을 의미하며, 이들에 대해 보안을 적용하지 않음으로써 성능을 향상시킬 수 있다.
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtAuthorizationFilter jwtAuthorizationFilter) throws Exception {
        log.info("filter Chain 들어옴.");

        /** Thread 간 공유 모드 설정
           1. MODE_THREADLOCAL: (Default) Local Thread 에서만 공유 가능
           2. MODE_INHERITABLETHREADLOCAL: Local Thread 에서 생성한 하위 Thread 에까지 공유 가능
           3. MODE_GLOCAL: 모든 Thread, 어플리케이션 전체에서 공유 가능
        */
//        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);


        http
                // custom session 로그인 시에도 disable로 열어줘야함.
                // csrf : 공격자가 인증된 브라우저에 저장된 쿠키의 세션 정보를 활용하여 웹 서버에 사용자가 의도하지 않은 요청을 전달하는 것 => 허용 시 : GET요청을 제외한 상태를 변화시킬 수 있는 POST, PUT, DELETE 요청으로부터 보호함
                // rest api 시 왜 disable 하는 걸까? : session 기반 인증과는 다르게 stateless하기 때문에 서버에 인증정보를 보관하지 않기 때문에
                .csrf(AbstractHttpConfigurer::disable) // .csrf(csrfConfig -> csrfConfig.disable())
                .csrf(Customizer.withDefaults())

                // cors : 다른 도메인의 리소스에서 나의 웹 리소스에 접근할 수 있도록 허용하는 메커니즘
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                .headers(headersConfigurer ->
                        // SAME ORIGIN : 같은 도메인 내에서의 참조만 허용하겠다
                        headersConfigurer.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin) //  headersConfigurer.frameOptions(frameOptionsConfig -> frameOptionsConfig.disable())
                )

                // 세션 관리를 해주는 역할
                // 세션 설정 -> rest api일 때 stateless 사용
//                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(authorizeRequest ->
                        authorizeRequest
                                .requestMatchers("/auth/**").hasAnyRole("USER")
                                .requestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")).permitAll() // h2-console 사용시 서블릿 컨텍스트에 h2-console과 dispatcherServlet의 두 가지 서블릿이 매핑되어 어떤 서블릿을 사용해야하는지 알 수 없어서 발생하는 오류 => 무슨 servlet(MvcRequestMatcher, AntPathRequestMatcher)을 사용할지 선택해준다.
                                .requestMatchers("/").permitAll()
                                .requestMatchers("/login", "/user").permitAll()
                )

                // 401, 403 관련 예외처리
//                .exceptionHandling((exceptionConfig) -> exceptionConfig
//                        .authenticationEntryPoint(unauthorizedEntryPoint)
//                        .accessDeniedHandler(accessDeniedHandler) // method
//                        .accessDeniedHandler(customAccessDeniedHandler) // class
//                )

                .formLogin((formLogin) -> formLogin // .formLogin(AbstractHttpConfigurer::disable)
                        .loginPage("/login")
                        .usernameParameter("username")
                        .passwordParameter("password")
                        .loginProcessingUrl("/login/login-proc")
                        .successForwardUrl("/")
                )
                .logout(logoutConfig -> logoutConfig.logoutSuccessUrl("/login"))


                // 세션 기반의 custom 인증 방식 사용
                .addFilterBefore(customAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);


//        customFilter(별도의 인증 로직을 가진 필터) 실행 후 UsernamePasswordAuthenticationFilter(인증을 처리하는 기본필터)가 실행됨. => 오버라이드 x
//        http.addFilterBefore(customJwtFilter, BasicAuthenticationFilter.class);

        return http.build();
    }

//    /**
//     * spring security에서 지정 username과 password로 진입할 수 있도록 해주는 역할
//     * */
//    @Autowired
//    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
//        auth
//                .inMemoryAuthentication()
//                .withUser("user").password(passwordEncoder().encode("password")).roles("USER")
//                .and()
//                .withUser("admin").password(passwordEncoder().encode("admin")).roles("ADMIN");
//    }

    /**
     * cors 설정
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        configuration.setAllowedHeaders(Arrays.asList("X-Requested-With", "Content-Type", "Authorization", "X-XSRF-token"));
        configuration.setAllowCredentials(false);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    /**
     * 에러 exception 핸들링 : error 응답용
     * */
    @Getter
    @RequiredArgsConstructor
    public class ErrorResponse {

        private final HttpStatus status;
        private final String message;
    }

    /**
     * 에러 exception 핸들링 : 401 - 인증되지 않은
     * */
    private final AuthenticationEntryPoint unauthorizedEntryPoint = (request, response, authException) -> {
        ErrorResponse fail = new ErrorResponse(HttpStatus.UNAUTHORIZED, "Spring security unauthorized...");
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        String json = new ObjectMapper().writeValueAsString(fail);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        PrintWriter writer = response.getWriter();
        writer.write(json);
        writer.flush();
    };

    /**
     * 에러 exception 핸들링 : 403 - 권한이 없는
     * */
    private final AccessDeniedHandler accessDeniedHandler = (request, response, accessDeniedException) -> {
        ErrorResponse fail = new ErrorResponse(HttpStatus.FORBIDDEN, "Spring security forbidden...");
        response.setStatus(HttpStatus.FORBIDDEN.value());
        String json = new ObjectMapper().writeValueAsString(fail);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        PrintWriter writer = response.getWriter();
        writer.write(json);
        writer.flush();
    };


// =================================================================================================
// 세션 기반의 custom 인증 방식

    /**
     * 1. 커스텀을 수행한 '인증' 필터로 접근 URL, 데이터 전달방식(form) 등 인증 과정 및 인증 후 처리에 대한 설정을 구성하는 메서드다.
     * 이 메서드는 사용자 정의 인증 필터를 생성한다. 이 필터는 로그인 요청을 처리하고, 인증 성공/실패 핸들러를 설정한다.
     *
     * @return CustomAuthenticationFilter
     */
    @Bean
    public CustomAuthenticationFilter customAuthenticationFilter() throws Exception {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManager());
        // "/user/login" 엔드포인트로 들어오는 요청을 CustomAuthenticationFilter에서 처리하도록 지정한다.
        customAuthenticationFilter.setFilterProcessesUrl("/login/login-proc");
        customAuthenticationFilter.setAuthenticationSuccessHandler(customLoginSuccessHandler());    // '인증' 성공 시 해당 핸들러로 처리를 전가한다.
        customAuthenticationFilter.setAuthenticationFailureHandler(customLoginFailureHandler());    // '인증' 실패 시 해당 핸들러로 처리를 전가한다.
        
        /**
         *  spring security 6.x 버전으로 업한뒤 문제점 : 로그인 후 SecurityContextHolder.getContext().getAuthentication()의 유지가 안됨.
         *      => 로그인 후 페이지 전환 시 SecurityContextHolder.getContext().getAuthentication() = null 로 나오는 현상
         *  
         *  해결방법 : setSecurityContextRepository 설정
         * */
        customAuthenticationFilter.setSecurityContextRepository(new DelegatingSecurityContextRepository(
                new HttpSessionSecurityContextRepository(),
                new RequestAttributeSecurityContextRepository()
        ));
        customAuthenticationFilter.afterPropertiesSet();
        return customAuthenticationFilter;
    }

    /**
     * 2. authenticate 의 인증 메서드를 제공하는 매니져로'Provider'의 인터페이스를 의미한다.
     * 이 메서드는 인증 매니저를 생성한다. 인증 매니저는 인증 과정을 처리하는 역할을 한다.
     * 과정: CustomAuthenticationFilter → AuthenticationManager(interface) → CustomAuthenticationProvider(implements)
     */
    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * 3. '인증' 제공자로 사용자의 이름과 비밀번호가 요구된다.
     * 이 메서드는 사용자 정의 인증 제공자를 생성한다. 인증 제공자는 사용자 이름과 비밀번호를 사용하여 인증을 수행한다.
     * 과정: CustomAuthenticationFilter → AuthenticationManager(interface) → CustomAuthenticationProvider(implements)
     */
    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider() {
        return new CustomAuthenticationProvider(
                userDetailsService
        );
    }

    /**
     * 4. Spring Security 기반의 사용자의 정보가 맞을 경우 수행이 되며 결과값을 리턴해주는 Handler
     * customLoginSuccessHandler: 이 메서드는 인증 성공 핸들러를 생성한다. 인증 성공 핸들러는 인증 성공시 수행할 작업을 정의한다.
     */
    @Bean
    public CustomAuthSuccessHandler customLoginSuccessHandler() {
        return new CustomAuthSuccessHandler();
    }

    /**
     * 5. Spring Security 기반의 사용자의 정보가 맞지 않을 경우 수행이 되며 결과값을 리턴해주는 Handler
     * customLoginFailureHandler: 이 메서드는 인증 실패 핸들러를 생성한다. 인증 실패 핸들러는 인증 실패시 수행할 작업을 정의한다.
     */
    @Bean
    public CustomAuthFailureHandler customLoginFailureHandler() {
        return new CustomAuthFailureHandler();
    }


// ================================================================================================================
// JWT 기반의 인증 방식

    @Bean
    public JwtAuthorizationFilter customJwtFilter(UserDetailsService userDetailsService) {
        return new JwtAuthorizationFilter(userDetailsService);
    }



    @Bean
    public static BCryptPasswordEncoder passwordEncoder() { // static 없을 시 순환 참조 발생
        return new BCryptPasswordEncoder();
    }
}


/**
 * 출처
 * 기본 설정 : https://velog.io/@kide77/Spring-Boot-3.x-Security-%EA%B8%B0%EB%B3%B8-%EC%84%A4%EC%A0%95-%EB%B0%8F-%EB%B3%80%ED%99%94
 * 전체적인 설정 및 설명 : https://curiousjinan.tistory.com/entry/spring-boot-3-1-security-6-security-config-class-detail-2
 * csrf.disable() 설정 이유 : https://velog.io/@wonizizi99/SpringSpring-security-CSRF%EB%9E%80-disable
 * configureGlobal 설정 : https://www.baeldung.com/spring-security-thymeleaf
 * authorizeHttpRequests에서 AntPathRequestMatcher를 사용하는 이유 : https://devpad.tistory.com/138
 * 401,403 에러 설정 : https://velog.io/@woosim34/Spring-Spring-Security-%EC%84%A4%EC%A0%95-%EB%B0%8F-%EA%B5%AC%ED%98%84SessionSpring-boot3.0-%EC%9D%B4%EC%83%81
 * filter 설정 및 설명 : https://kimchanjung.github.io/programming/2020/07/02/spring-security-02/
 * JSON-parse 라이브러리 : https://velog.io/@chosj1526/Java-JSON-%EB%9D%BC%EC%9D%B4%EB%B8%8C%EB%9F%AC%EB%A6%AC-%EC%82%AC%EC%9A%A9-%EB%B0%A9%EB%B2%95-JSONObject-JSONArray-JsonParser%EB%A1%9C-%ED%8C%8C%EC%8B%B1%ED%95%98%EA%B8%B0
 * +) JWT : https://dchkang83.tistory.com/25
 * ★인증 객체 저장 및 유지를 위한 설정 : https://velog.io/@kide77/Security-6.x-%EC%97%90%EC%84%9C-SecurityContextHolder-%EC%9D%B8%EC%A6%9D-%EA%B0%9D%EC%B2%B4-%EC%A0%80%EC%9E%A5%EC%9D%84-%EC%9C%84%ED%95%9C-%EC%84%A4%EC%A0%95
 *  => Security 6.x 버전 이상부터는 커스텀한 로그인 로직에 SecurityContextHolder 에 인증 객체를 직접 넣어 쓸 경우에는 SecurityContextRepository 를 설정해줘야 한다.
 */