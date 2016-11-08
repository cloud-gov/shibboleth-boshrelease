// $Id: DBLogin.java,v 1.5 2003/02/17 20:13:23 andy Exp $
package com.tagish.auth;

import java.util.Map;
import java.util.*;
import java.sql.*;
import javax.security.auth.*;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Simple database based authentication module.
 *
 * @author Andy Armstrong, <A HREF="mailto:andy@tagish.com">andy@tagish.com</A>
 * @version 1.0.3
 */
public class DBLogin extends SimpleLogin
{
	protected String                dbDriver;
	protected String                dbURL;
	protected String                dbUser;
	protected String                dbPassword;
	protected String                userTable;
	protected String                userColumn;
	protected String                passColumn;
	protected String 				passLastModifiedColumn;
	protected String                where;
	protected String				useBcrypt;
	protected String 				passExpirationDays;

	private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();


	protected synchronized Vector validateUser(String username, char password[]) throws LoginException
	{
		ResultSet rsu = null, rsr = null;
		Connection con = null;
		PreparedStatement psu = null;

		try
		{
			Class.forName(dbDriver);
			if (dbUser != null)
			   con = DriverManager.getConnection(dbURL, dbUser, dbPassword);
			else
			   con = DriverManager.getConnection(dbURL);

			psu = con.prepareStatement("SELECT " + passColumn + ", " + passLastModifiedColumn +
										" FROM " + userTable +
										" WHERE " + userColumn + "=?" + where);

			/* Set the username to the statement */
			psu.setString(1, username);
			rsu = psu.executeQuery();
			if (!rsu.next()) throw new FailedLoginException("Unknown user");
			String upwd = rsu.getString(1);
			String tpwd = new String(password);
			java.util.Date pwlm = rsu.getTimestamp(2);

			/* Check the password */
			if (useBcrypt.equals("false")) {
				if (!upwd.equals(tpwd)) throw new FailedLoginException("Bad password");
			} else {
				if (!passwordEncoder.matches(tpwd, upwd)) throw new FailedLoginException("Bad password");
			}
			psu.close();

			java.util.Date now = new java.util.Date();
			if (daysBetween(now, pwlm) > Integer.parseInt(passExpirationDays))
				throw new CredentialExpiredException("Password has expired");

			Vector p = new Vector();
			p.add(new TypedPrincipal(username, TypedPrincipal.USER));
			return p;
		}
		catch (ClassNotFoundException e)
		{
			throw new LoginException("Error reading user database (" + e.getMessage() + ")");
		}
		catch (SQLException e)
		{
			throw new LoginException("Error reading user database (" + e.getMessage() + ")");
		}
		finally
		{
			try {
				if (rsu != null) rsu.close();
				if (rsr != null) rsr.close();
				if (psu != null) psu.close();
				if (con != null) con.close();
			} catch (Exception e) { }
		}
	}

	private static long daysBetween(java.util.Date one, java.util.Date two) {
		long difference = (one.getTime()-two.getTime())/86400000;
		return Math.abs(difference);
	}

	public void initialize(Subject subject, CallbackHandler callbackHandler, Map sharedState, Map options)
	{
		super.initialize(subject, callbackHandler, sharedState, options);

		dbDriver = getOption("dbDriver", null);
		if (dbDriver == null) throw new Error("No database driver named (dbDriver=?)");
		dbURL = getOption("dbURL", null);
		if (dbURL == null) throw new Error("No database URL specified (dbURL=?)");
		dbUser = getOption("dbUser", null);
		dbPassword = getOption("dbPassword", null);
		if ((dbUser == null && dbPassword != null) || (dbUser != null && dbPassword == null))
		   throw new Error("Either provide dbUser and dbPassword or encode both in dbURL");

		userTable    = getOption("userTable",    "User");
		userColumn   = getOption("userColumn",   "user_name");
		passColumn   = getOption("passColumn",   "user_passwd");
		passColumn   = getOption("passColumn",   "user_passwd");
		passLastModifiedColumn = getOption("passLastModifiedColumn",   "passwd_lastmodified");
		passExpirationDays = getOption("passExpirationDays",   "90");
		useBcrypt	 = getOption("useBcrypt",    "true");
		where        = getOption("where",        "");
		if (null != where && where.length() > 0)
			where = " AND " + where;
		else
			where = "";
	}
}
