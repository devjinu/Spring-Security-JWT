package com.jwt.springsecurityjwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jwt.springsecurityjwt.config.auth.PrincipalDetails;
import com.jwt.springsecurityjwt.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter가 존재
// /login 요청으로 username,password 전송하면(post)
// UsernamePasswordAuthenticationFilter가 동작
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 로그인 시도 중");

        // 1. username, password -> 정상인지 로그인 시도
        // 2. authenticationManager로 로그인 시도 -> PrincipalDetailsService가 호출 -> loadUserByUsername() 실행
        // 3. PrincipalDetails를 세션에 담고 (권한 관리를 위해)
        // 4. JWT토큰을 만들어서 응답

        try {

           /* BufferedReader br = request.getReader();
            String input = null;

            while ((input = br.readLine()) != null) {
                System.out.println(input);
            }*/

            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(" user "+user);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService가 호출 -> loadUserByUsername() 실행된 후 정상이면 authentication이 리턴
            // DB에 있는 username, password 일치
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료됨 : "+principalDetails.getUser().getUsername()); // -> 로그인이 완료

            // 리턴될 때 authentication 객체가 session 영역에 저장
            // 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하기위해 하는거임
            // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없음, 단지 권한처리때문에 session에 넣어줌
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("--------------------------------------");

        return null;
    }


    // attemptAuthentication실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행
    // JWT 토큰을 만들어서 request 요청한 사용자에게 JWT토큰을 response해주면 됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행 -> 인증 완료");

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // Hash암호방식 RSA - x
        String jwtToken = JWT.create()
                .withSubject("jwt토큰")
                .withExpiresAt(new Date(System.currentTimeMillis()+(60000*10)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("moon"));

        response.addHeader("Authorization", "Bearer "+jwtToken);
    }
}
