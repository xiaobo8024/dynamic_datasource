package com.itsm.security.filter;

import org.apache.commons.lang3.StringUtils;
//import org.apache.tomcat.util.http.ResponseUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.PathMatcher;
//import org.springframework.web.filter.OncePerRequestFilter;

import com.alibaba.fastjson.JSONObject;

//import com.itsm.api.cnki.bean.CasDbBean;
//import com.itsm.common.returned.ResponseUtil;
//import com.itsm.common.returned.ResultCode;
//import com.itsm.common.returned.ResultGenerator;
//import com.itsm.common.datasource.DruidDataSourceUtil;
//import com.itsm.common.redis.JedisUtils;
//import com.itsm.common.redis.RedisConstants;
//import com.itsm.security.jwt.JwtTokenUtil;
//import com.itsm.util.AESUtil;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

//@Component
//public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {
//    Logger logger = LoggerFactory.getLogger(this.getClass());
//
//    @Autowired
//    private UserDetailsService userDetailsService;
//
//    @Autowired
//    ResultGenerator resultGenerator;
//
//    @Autowired
//    private PathMatcher pathMatcher;
//
//    @Autowired
//    private JwtTokenUtil jwtTokenUtil;
//
//    @Autowired
//    JedisUtils jedisUtils;
//
//    @Value("${jwt.token.header}")
//    private String token_header;
//    @Value("${jwt.token.type}")
//    private String token_type;
//    @Value("${jwt.token.passUrl}")
//    private List<String> passUrl;
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
//            throws ServletException, IOException {
//        String requestUrl = request.getRequestURI();
//        logger.info("["+requestUrl+"]访问校验jwt,并将用户角色信息写入内存!");
//        //判断URL是否需要验证
//        Boolean flag = true;
//        for(String url : passUrl){
//            if(pathMatcher.match(url, requestUrl)){
//                flag = false;
//                break;
//            }
//        }
//
//        //根据判断结果执行校验
//        if (flag) {
//            String authHeader = request.getHeader(this.token_header);
//            if (authHeader != null && authHeader.startsWith(this.token_type)) {
//                //获取token
//                String authToken = authHeader.substring(this.token_type.length());
//                if (!jwtTokenUtil.isTokenExpired(authToken)) {//无效token去更新
//                    //根据token获取用户名
//                    String username = jwtTokenUtil.getUserNameFromToken(authToken);
//                    if (username != null) {
//                        String retoken = jedisUtils.get(username, RedisConstants.datebase1);
//                        if (StringUtils.isEmpty(retoken)) {
//                            logger.error("用户："+username+" 访问url:["+requestUrl+"]校验失败，未登录!");
//                            ResponseUtil.out(response, 402, resultGenerator.getFreeResult(ResultCode.LOGIN_NO).toString());
//                            return;
//                        }
//                        //获取用户对应数据源
//                        String dbStr = jedisUtils.get(username,RedisConstants.datebase2);
//                        if (dbStr != null) {
//                            String dbinfo = AESUtil.decryptPwd(dbStr);
//                            CasDbBean casDbBean = JSONObject.parseObject(dbinfo, CasDbBean.class);
//                            DruidDataSourceUtil.addOrChangeDataSource(casDbBean.getSchoolId(),casDbBean.getDbIp(),casDbBean.getDbName(),casDbBean.getDbUser(),casDbBean.getDbPassword());
//                        }
//
//                        UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
//                        if (jwtTokenUtil.validateToken(authToken, userDetails) && !StringUtils.isEmpty(retoken)) {
//                            //验证token是否有效
//                            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
//                            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//                            SecurityContextHolder.getContext().setAuthentication(authentication);
//
//                            chain.doFilter(request, response);
//                            return;
//                        }
//                    }
//                }
//            }
//        }else {//无需校验直接通过
//            chain.doFilter(request, response);
//            return;
//        }
//        logger.error("访问url:["+requestUrl+"]校验失败，无权访问!");
//        ResponseUtil.out(response, 403, resultGenerator.getFreeResult(ResultCode.NO_PERMISSION).toString());
//    }

//}
