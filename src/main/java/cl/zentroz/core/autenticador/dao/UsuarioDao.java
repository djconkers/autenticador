package cl.zentroz.core.autenticador.dao;

import org.apache.ibatis.session.SqlSession;
import org.springframework.stereotype.Repository;

import cl.zentroz.biblioteca.dao.DAO;
import cl.zentroz.core.autenticador.dto.Usuario;


@Repository
public class UsuarioDao extends DAO<Usuario>{

	public UsuarioDao(SqlSession sqlSession) {
		super(sqlSession);
		// TODO Auto-generated constructor stub
	}
	
	public int updateUsuarioPass(Usuario entidad)
	{
		return this.sqlSession.update("updateUsuarioPass", entidad);
	}

}
