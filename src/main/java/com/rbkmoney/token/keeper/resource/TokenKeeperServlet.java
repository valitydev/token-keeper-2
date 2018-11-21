package com.rbkmoney.token.keeper.resource;

import com.rbkmoney.token.keeper.TokenKeeperSrv;
import com.rbkmoney.woody.thrift.impl.http.THServiceBuilder;
import lombok.RequiredArgsConstructor;

import javax.servlet.*;
import javax.servlet.annotation.WebServlet;
import java.io.IOException;

/**
 * @author k.struzhkin on 11/21/18
 */
@WebServlet("/token_keeper")
@RequiredArgsConstructor
public class TokenKeeperServlet extends GenericServlet {

    private Servlet thriftServlet;

    private final TokenKeeperSrv.Iface requestHandler;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        thriftServlet = new THServiceBuilder()
                .build(TokenKeeperSrv.Iface.class, requestHandler);
    }

    @Override
    public void service(ServletRequest req, ServletResponse res) throws ServletException, IOException {
        thriftServlet.service(req, res);
    }
}
