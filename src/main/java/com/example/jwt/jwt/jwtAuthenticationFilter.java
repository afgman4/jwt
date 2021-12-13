package com.example.jwt.jwt;

import com.example.jwt.auth.PrincipalDetails;
import com.example.jwt.model.User;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter 가 있음
// login 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter 동작을 함
@RequiredArgsConstructor
public class jwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter: 로그인 시도중");
        //1. username, password 받아서
        try{

//            BufferedReader br = request.getReader();
//            String input = null;
//            while((input=br.readLine())!=null){
//                System.out.println(input);
//            }

            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println("user : " + user);
            //2. 정상인지 로그인 시도를 해봄 authenticationManager로 로그인 시도를 하면
            //   PrincipalDetailsService가 호출되어 loadUserByUsername이 호출됨
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword());

            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // authentication 객체가 session영역에 저장됨 => 로그인 되었다는 뜻
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getDetails();
            System.out.println(principalDetails.getUser().getUsername());

            return authentication;
        }catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("============================================");

        //3. PrincipalDetails를 세션에 담고 (세션에 안담으면 권한관리가 안됨 SecurityConfig에 설정된 것들이 적용이 안됨됨)
        //4. jwt토큰을 만들어서 응답해주면 됨
        return null;
    }
}
