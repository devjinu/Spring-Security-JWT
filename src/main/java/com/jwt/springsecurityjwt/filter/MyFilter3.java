package com.jwt.springsecurityjwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) servletRequest;
        HttpServletResponse res = (HttpServletResponse) servletResponse;


        // 토큰 : hello -> id, password 정상적으로 들어와서 로그인이 완료되면, 토큰을 만들어주고 그걸 응답을 해준다
        // 요청할 때 마다 header에 Authorization에 value값으로 토큰을 가지고 넘어오면 이 토큰이 내가만든 토큰이 맞는지만 검증하면 됨(RSA, HS256)
        if (req.getMethod().equals("POST")) {
            System.out.println("post 요청됨");
            String headerAuth = req.getHeader("Authorization");
            System.out.println(" headerAuth : " + headerAuth);
            System.out.println("필터3");

            if (headerAuth.equals("hello")) {
                filterChain.doFilter(req, res);
            } else {
                PrintWriter writer = res.getWriter();
                writer.println("인증 되지 않음");
            }
        }

    }
}
