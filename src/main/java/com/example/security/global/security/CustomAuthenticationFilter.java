package com.example.security.global.security;

import com.example.security.domain.member.member.entity.Member;
import com.example.security.domain.member.member.service.MemberService;
import com.example.security.global.Rq;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationFilter extends OncePerRequestFilter {

    private final Rq rq;
    private final MemberService memberService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String authorizationHeader = request.getHeader("Authorization");

        if (authorizationHeader == null) {
            filterChain.doFilter(request, response);
            return;
        }

        if (!authorizationHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String apiKey = authorizationHeader.substring("Bearer ".length());

        Optional<Member> opMember = memberService.findByApiKey(apiKey);

        if (opMember.isEmpty()) {
            filterChain.doFilter(request, response);
            return;
        }

        Member actor = opMember.get();
        rq.setLogin(actor.getUsername());

        filterChain.doFilter(request, response);
    }
}