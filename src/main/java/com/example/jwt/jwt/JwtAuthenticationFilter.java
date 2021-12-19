package com.example.jwt.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.auth.PrincipalDetails;
import com.example.jwt.model.User;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter 가 있음
// login 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter 동작을 함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter: 로그인 시도중");
        //1. username, password 받아서
        try{

            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println("user : " + user);

            String aa = new BCryptPasswordEncoder().encode(user.getPassword());
            //2. 정상인지 로그인 시도를 해봄 authenticationManager로 로그인 시도를 하면
            //   PrincipalDetailsService가 호출되어 loadUserByUsername이 호출됨

            //3. PrincipalDetails를 세션에 담고(권한 관리를 위해서)
            //4. jwt 토큰을 만들어서 응답해주면 됨
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword());

            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행됨
            // DB에 있는 username과 password가 일치한다.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // authentication 객체가 session영역에 저장됨 => 로그인 되었다는 뜻
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료됨 " + principalDetails.getUser().getUsername());

            // authentication 객체가 session영역에 저장을 해야 하고 그 방법이 return 해주면 됨
            // 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는것임
            // 굳이 jwt 토큰을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한 처리 때문에 session에 넣어줌

            return authentication;
        }catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("============================================");

        //3. PrincipalDetails를 세션에 담고 (세션에 안담으면 권한관리가 안됨 SecurityConfig에 설정된 것들이 적용이 안됨됨)
        //4. jwt토큰을 만들어서 응답해주면 됨
        return null;
    }

    // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행됨
    // jwt 토큰을 만들어서 request 요청한 사용자들에게 jwt 토큰을  response 해주면 됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨 : 인증이 완료되었다는 뜻임");
        PrincipalDetails principalDetails = (PrincipalDetails)authResult.getPrincipal();

        String jwtToken = JWT.create().withSubject(principalDetails.getUsername())
                                        .withExpiresAt(new Date(System.currentTimeMillis()+(JwtProperties.EXPIRATION_TIME)))
                                        .withClaim("id", principalDetails.getUser().getId())
                                        .withClaim("username", principalDetails.getUser().getUsername())
                                        .sign(Algorithm.HMAC512(JwtProperties.SECRET));

        response.addHeader(JwtProperties.HEADER_STRING,JwtProperties.TOKEN_PREFIX + jwtToken);
    }
}
