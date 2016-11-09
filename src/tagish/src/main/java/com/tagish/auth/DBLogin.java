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
	protected String                passLastModifiedColumn;
	protected String               	where;
	protected String				useBcrypt;
	protected String                passExpirationDays;
	protected String                auditTable;
	protected String                principalIdColumn;
	protected String                eventTypeColumn;
	protected String 				eventDateColumn;
	protected String                originColumn;
	protected String                origin;
	protected String 				failurePeriodSeconds;
	protected String 				lockoutPeriodSeconds;
	protected String 				failureCount;

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
			if (!rsu.next()) {
				if (!auditTable.isEmpty()) {
					logEvent(con, username, AuditEventType.UserNotFound);
				}
				throw new FailedLoginException("Unknown user");
			}
			String upwd = rsu.getString(1);
			String tpwd = new String(password);
			java.util.Date pwlm = rsu.getTimestamp(2);

			/* Check the password */
			if (useBcrypt.equals("false")) {
				if (!upwd.equals(tpwd)) {
					if (!auditTable.isEmpty()) {
						logEvent(con, username, AuditEventType.UserAuthenticationFailure);
					}
					if (!auditTable.isEmpty() &&
						(getFailedLoginCount(con, username, AuditEventType.UserAuthenticationFailure) >=
							Integer.parseInt(failureCount))) {
						throw new AccountLockedException("Account is locked");
					} else {
						throw new FailedLoginException("Bad password");
					}
				}
			} else {
				if (!passwordEncoder.matches(tpwd, upwd)) {
					if (!auditTable.isEmpty()) {
						logEvent(con, username, AuditEventType.UserAuthenticationFailure);
					}
					if (!auditTable.isEmpty() &&
						(getFailedLoginCount(con, username, AuditEventType.UserAuthenticationFailure) >=
							Integer.parseInt(failureCount))) {
						throw new AccountLockedException("Account is locked");
					} else {
						throw new FailedLoginException("Bad password");
					}
				}
			}
			psu.close();

			java.util.Date now = new java.util.Date();
			if (intervalBetween(now, pwlm, Interval.DAYS) >= Integer.parseInt(passExpirationDays))
				throw new CredentialExpiredException("Password has expired");

			if (!auditTable.isEmpty() &&
				(getFailedLoginCount(con, username, AuditEventType.UserAuthenticationFailure) >=
					Integer.parseInt(failureCount))) {
				throw new AccountLockedException("Account is locked");
			}

			if (!auditTable.isEmpty()) {
				logEvent(con, username, AuditEventType.UserAuthenticationSuccess);
			}
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

	private int getFailedLoginCount(Connection con, String username, AuditEventType event) {

		ResultSet rsu = null, rsr = null;
		PreparedStatement psu = null;
		int failureCount = 0;

		try {
			psu = con.prepareStatement("SELECT " + eventTypeColumn +
										" FROM " + auditTable +
										" WHERE " + principalIdColumn + "=?" +
										" AND " + eventDateColumn + ">= ?" +
										" AND " + eventDateColumn + ">= ?" +
										" ORDER BY " + eventDateColumn);

			java.util.Date now = new java.util.Date();
			java.util.Date limitDate = new java.util.Date(now.getTime() -
				(Integer.parseInt(failurePeriodSeconds) * 1000));
			java.util.Date lockoutPeriodDate = new java.util.Date(now.getTime() -
				(Integer.parseInt(lockoutPeriodSeconds) * 1000));

			/* Set the username to the statement */
			psu.setString(1, username);
			psu.setTime(2, new java.sql.Time(limitDate.getTime()));
			psu.setTime(3, new java.sql.Time(lockoutPeriodDate.getTime()));

			rsu = psu.executeQuery();

			while (rsu.next()) {
	            if (event == AuditEventType.UserAuthenticationFailure) {
	                failureCount++;
	            } else if (event == AuditEventType.UserAuthenticationSuccess) {
	                // Successful authentication occurred within last allowable
	                // failures, so ignore
	                break;
	            }
	        }

	    } catch (Exception e) { }

        return failureCount;

    }

	private void logEvent(Connection con, String username, AuditEventType eventType) {

		ResultSet rsu = null, rsr = null;
		PreparedStatement psu = null;

		try {
			psu = con.prepareStatement("INSERT INTO " + auditTable + " (" + principalIdColumn +
										", " + eventTypeColumn + ", " + eventDateColumn + ", " + originColumn + ") " +
										"values (?, ?, ?, ?)");

			/* Set the username to the statement */

			java.util.Date now = new java.util.Date();
			psu.setString(1, username);
			psu.setInt(2, eventType.getCode());
			psu.setTime(3, new java.sql.Time(now.getTime()));
			psu.setString(4, origin);
			rsu = psu.executeQuery();
		} catch (Exception e) { }

	}

	private static long intervalBetween(java.util.Date one, java.util.Date two, Interval interval) {
		long difference = (one.getTime()-two.getTime())/interval.getMiliseconds();
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
		passLastModifiedColumn = getOption("passLastModifiedColumn",   "passwd_lastmodified");
		passExpirationDays = getOption("passExpirationDays",   "90");
		useBcrypt	 = getOption("useBcrypt",    "true");
		auditTable   = getOption("auditTable",   "");
		principalIdColumn = getOption("principalIdColumn",   "principal_id");
		eventTypeColumn = getOption("eventTypeColumn",   "event_type");
		originColumn = getOption("originColumn",   "origin");
		origin       = getOption("origin",   "shibboleth");
		failureCount = getOption("failureCount", "5");
		failurePeriodSeconds = getOption("failurePeriodSeconds", "1200");
		lockoutPeriodSeconds = getOption("lockoutPeriodSeconds", "300");
		where        = getOption("where",        "");
		if (null != where && where.length() > 0)
			where = " AND " + where;
		else
			where = "";
	}

	private enum AuditEventType {

	    // Do not change the code values, as these are used in the database.
	    UserAuthenticationSuccess(0),
	    UserAuthenticationFailure(1),
	    UserNotFound(2);

	    private final int code;

	    private AuditEventType(int code) {
	        this.code = code;
	    }

	    public static AuditEventType fromCode(int code) {
	        for (AuditEventType a : AuditEventType.values()) {
	            if (a.getCode() == code) {
	                return a;
	            }
	        }
	        throw new IllegalArgumentException("No event type with code " + code + " exists");
	    }

	    public int getCode() {
	        return code;
	    }
	}

	private enum Interval {
		/* miliseconds for each interval */
		DAYS(86400000),
		MINUTES(60000),
		SECONDS(1000);

		private final int miliseconds;

		private Interval(int miliseconds) {
			this.miliseconds = miliseconds;
		}

		public static Interval fromMiliseconds(int miliseconds) {
			for (Interval i : Interval.values()) {
				if (i.getMiliseconds() == miliseconds) {
					return i;
				}
			}
			throw new IllegalArgumentException("No interval with miliseconds value " + miliseconds);
		}

		public int getMiliseconds() {
			return miliseconds;
		}
	}


}
