package cl.zentroz.core.autenticador.dto;

import java.util.Date;

import cl.zentroz.biblioteca.dto.Entidad;


public class Usuario extends Entidad
{
	private String usuario;
	private String password;
	private String correo;
	private String steamId;
	private String arkId;
	private Long puntos;
	private Date fechaGacha;
	private Integer poder;
	private String comando;
	public Usuario() {
		super(null);
	}
	public String getUsuario() {
		return usuario;
	}
	public void setUsuario(String usuario) {
		this.usuario = usuario;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public String getCorreo() {
		return correo;
	}
	public void setCorreo(String correo) {
		this.correo = correo;
	}
	public String getSteamId() {
		return steamId;
	}
	public void setSteamId(String steamId) {
		this.steamId = steamId;
	}
	public String getArkId() {
		return arkId;
	}
	public void setArkId(String arkId) {
		this.arkId = arkId;
	}
	public Long getPuntos() {
		return puntos;
	}
	public void setPuntos(Long puntos) {
		this.puntos = puntos;
	}
	public Date getFechaGacha() {
		return fechaGacha;
	}
	public void setFechaGacha(Date fechaGacha) {
		this.fechaGacha = fechaGacha;
	}
	public Integer getPoder() {
		return poder;
	}
	public void setPoder(Integer poder) {
		this.poder = poder;
	}
	public String getComando() {
		return comando;
	}
	public void setComando(String comando) {
		this.comando = comando;
	}
	@Override
	public String toString() {
		return "Usuario [usuario=" + usuario + ", password=" + password + ", correo=" + correo + ", steamId=" + steamId
				+ ", arkId=" + arkId + ", puntos=" + puntos + ", fechaGacha=" + fechaGacha + ", poder=" + poder + "]";
	}
	
	
	
}
