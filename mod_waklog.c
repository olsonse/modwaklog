#include "httpd.h"
#include "http_config.h"
#include "http_conf_globals.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_core.h"
#include "ap_config.h"
#include <krb5.h>

#if defined(sun)
#include <sys/ioccom.h>
#endif /* sun */
#include <stropts.h>
#include <kerberosIV/krb.h>
#include <kerberosIV/des.h>
#include <afs/venus.h>
#include <afs/auth.h>
#include <rx/rxkad.h>

#include <asm/bitops.h>
#include <sys/shm.h>

#define KEYTAB_PATH "/home/drh/keytab.umweb.drhtest"
#define PRINCIPAL "umweb/drhtest"
#define AFS "afs"
#define IN_TKT_SERVICE "krbtgt/UMICH.EDU"

#define K5PATH "FILE:/tmp/waklog.creds.k5"
#define K4PATH "/tmp/waklog.creds.k4"

module waklog_module;

struct ClearToken {
    long AuthHandle;
    char HandShakeKey[ 8 ];
    long ViceId;
    long BeginTimestamp;
    long EndTimestamp;
};

typedef struct {
    int		configured;
    int		protect;
    char	*keytab;
    char	*keytab_principal;
    char	*afs_instance;
} waklog_host_config;

typedef struct {
	struct ktc_token	token;
} waklog_child_config;
waklog_child_config	*child = NULL;


    static void *
waklog_create_dir_config( pool *p, char *path )
{
    waklog_host_config *cfg;

    cfg = (waklog_host_config *)ap_pcalloc( p, sizeof( waklog_host_config ));
    cfg->configured = 0;
    cfg->protect = 0;
    cfg->keytab = 0;
    cfg->keytab_principal = 0;
    cfg->afs_instance = 0;

    return( cfg );
}


    static void *
waklog_create_server_config( pool *p, server_rec *s )
{
    waklog_host_config *cfg;

    cfg = (waklog_host_config *)ap_pcalloc( p, sizeof( waklog_host_config ));
    cfg->configured = 0;
    cfg->protect = 0;
    cfg->keytab = 0;
    cfg->keytab_principal = 0;
    cfg->afs_instance = 0;

    return( cfg );
}


    static const char *
set_waklog_protect( cmd_parms *params, void *mconfig, int flag )
{
    waklog_host_config          *cfg;

    if ( params->path == NULL ) {
        cfg = (waklog_host_config *) ap_get_module_config(
                params->server->module_config, &waklog_module );
    } else {
        cfg = (waklog_host_config *)mconfig;
    }

    cfg->protect = flag;
    cfg->configured = 1;
    return( NULL );
}


    static const char *
set_waklog_use_keytab( cmd_parms *params, void *mconfig, char *file  )
{
    waklog_host_config          *cfg;

    if ( params->path == NULL ) {
        cfg = (waklog_host_config *) ap_get_module_config(
                params->server->module_config, &waklog_module );
    } else {
        cfg = (waklog_host_config *)mconfig;
    }

    ap_log_error( APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, params->server,
	    "mod_waklog: using keytab: %s", file );

    cfg->keytab = file;
    cfg->configured = 1;
    return( NULL );
}


    static void
waklog_child_init( server_rec *s, pool *p )
{

    if ( child  == NULL ) {
	child = (waklog_child_config *) ap_palloc( p, sizeof( waklog_child_config ) );
    }

    memset( &child->token, 0, sizeof( struct ktc_token ) );

    setpag();

    return;
}


command_rec waklog_cmds[ ] =
{
    { "WaklogProtected", set_waklog_protect,
    NULL, RSRC_CONF | ACCESS_CONF, FLAG,
    "enable waklog on a location or directory basis" },

    { "WaklogUseKeytab", set_waklog_use_keytab,
    NULL, RSRC_CONF, TAKE1,
    "Use the supplied keytab file rather than the user's TGT" },

    { NULL }
};


    static void
token_cleanup( void *data )
{
    request_rec		*r = (request_rec *)data;

    if ( child->token.ticketLen ) {
	memset( &child->token, 0, sizeof( struct ktc_token ) );

	ktc_ForgetAllTokens();

	ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
	    "mod_waklog: ktc_ForgetAllTokens succeeded" );
    }
    return;
}


    static int
waklog_kinit( server_rec *s )
{
    krb5_error_code		kerror;
    krb5_context		kcontext = NULL;
    krb5_principal		kprinc = NULL;
    krb5_get_init_creds_opt	kopts;
    krb5_creds			v5creds;
    CREDENTIALS			v4creds;
    krb5_ccache			kccache = NULL;
    krb5_keytab			keytab = NULL;
    char			ktbuf[ MAX_KEYTAB_NAME_LEN + 1 ];
    waklog_host_config		*cfg;

    ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, s,
	"mod_waklog: waklog_kinit called" );

    if (( kerror = krb5_init_context( &kcontext ))) {
	ap_log_error( APLOG_MARK, APLOG_ERR, s,
        	(char *)error_message( kerror ));

        goto cleanup;
    }

    /* use the path */
    if (( kerror = krb5_cc_resolve( kcontext, K5PATH, &kccache )) != 0 ) {
	ap_log_error( APLOG_MARK, APLOG_ERR, s,
		(char *)error_message( kerror ));

    	goto cleanup;
    }

   if (( kerror = krb5_parse_name( kcontext, PRINCIPAL, &kprinc ))) {
	ap_log_error( APLOG_MARK, APLOG_ERR, s,
		(char *)error_message( kerror ));

       	goto cleanup;
    }

    krb5_get_init_creds_opt_init( &kopts );
    krb5_get_init_creds_opt_set_tkt_life( &kopts, 10*60*60 );
    krb5_get_init_creds_opt_set_renew_life( &kopts, 0 );
    krb5_get_init_creds_opt_set_forwardable( &kopts, 1 );
    krb5_get_init_creds_opt_set_proxiable( &kopts, 0 );

    cfg = (waklog_host_config *) ap_get_module_config( s->module_config,
	    &waklog_module );

    /* which keytab should we use? */
    strcpy( ktbuf, cfg->keytab ? cfg->keytab : KEYTAB_PATH );

    if ( strlen( ktbuf ) > MAX_KEYTAB_NAME_LEN ) {
	ap_log_error( APLOG_MARK, APLOG_ERR, s,
		"server configuration error" );

	goto cleanup;
    }

    ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, s,
	    "mod_waklog: waklog_kinit using: %s", ktbuf );

    if (( kerror = krb5_kt_resolve( kcontext, ktbuf, &keytab )) != 0 ) {
	ap_log_error( APLOG_MARK, APLOG_ERR, s,
		(char *)error_message( kerror ));

    	goto cleanup;
    }

    /* get the krbtgt */
    if (( kerror = krb5_get_init_creds_keytab( kcontext, &v5creds, 
		kprinc, keytab, 0, IN_TKT_SERVICE, &kopts ))) {

	ap_log_error( APLOG_MARK, APLOG_ERR, s,
		(char *)error_message( kerror ));

    	goto cleanup;
    }

   if (( kerror = krb5_verify_init_creds( kcontext, &v5creds,
    	    kprinc, keytab, NULL, NULL )) != 0 ) {

	ap_log_error( APLOG_MARK, APLOG_ERR, s,
		(char *)error_message( kerror ));

    	goto cleanup;
    }

    if (( kerror = krb5_cc_initialize( kcontext, kccache, kprinc )) != 0 ) {
	ap_log_error( APLOG_MARK, APLOG_ERR, s,
		(char *)error_message( kerror ));

    	goto cleanup;
    }

    kerror = krb5_cc_store_cred( kcontext, kccache, &v5creds );
    krb5_free_cred_contents( kcontext, &v5creds );
    if ( kerror != 0 ) {
	ap_log_error( APLOG_MARK, APLOG_ERR, s,
		(char *)error_message( kerror ));

    	goto cleanup;
    }

    ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, s,
	"mod_waklog: waklog_kinit success" );

cleanup:
    if ( keytab )
	(void)krb5_kt_close( kcontext, keytab );
    if ( kprinc )
	krb5_free_principal( kcontext, kprinc );
    if ( kccache )
	krb5_cc_close( kcontext, kccache );
    if ( kcontext )
	krb5_free_context( kcontext );

    ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, s,
	"mod_waklog: waklog_kinit: exiting" );

    return( 0 );
}


    static void
waklog_aklog( request_rec *r )
{
    int				rc;
    char			buf[ 1024 ];
    const char          	*k4path = NULL;
    const char          	*k5path = NULL;
    krb5_error_code		kerror;
    krb5_context		kcontext = NULL;
    krb5_creds			increds;
    krb5_creds			*v5credsp = NULL;
    CREDENTIALS			v4creds;
    krb5_ccache			kccache = NULL;
    struct ktc_principal	server = { "afs", "", "umich.edu" };
    struct ktc_principal	client;
    struct ktc_token		token;

    k5path = ap_table_get( r->subprocess_env, "KRB5CCNAME" );
    k4path = ap_table_get( r->subprocess_env, "KRBTKFILE" );

    ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
	"mod_waklog: waklog_aklog called: k5path: %s, k4path: %s", k5path, k4path );

    if ( !k5path || !k4path ) {   
	ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
		"mod_waklog: waklog_aklog giving up" );
	goto cleanup;
    }

    /*
    ** Get/build creds from file/tgs, then see if we need to SetToken
    */

    if (( kerror = krb5_init_context( &kcontext ))) {
	/* Authentication Required ( kerberos error ) */
	ap_log_error( APLOG_MARK, APLOG_ERR, r->server,
		(char *)error_message( kerror ));

	goto cleanup;
    }

    memset( (char *)&increds, 0, sizeof(increds));

    /* set server part */
    if (( kerror = krb5_parse_name( kcontext, AFS, &increds.server ))) {
	ap_log_error( APLOG_MARK, APLOG_ERR, r->server,
		(char *)error_message( kerror ));

	goto cleanup;
    }

    if (( kerror = krb5_cc_resolve( kcontext, k5path, &kccache )) != 0 ) {
    	ap_log_error( APLOG_MARK, APLOG_ERR, r->server,
    		(char *)error_message( kerror ));
    
        goto cleanup;
    }

    /* set client part */
    krb5_cc_get_principal( kcontext, kccache, &increds.client );

    increds.times.endtime = 0;
    /* Ask for DES since that is what V4 understands */
    increds.keyblock.enctype = ENCTYPE_DES_CBC_CRC;

    /* get the V5 credentials */
    if (( kerror = krb5_get_credentials( kcontext, 0, kccache,
		&increds, &v5credsp ) ) ) {
	ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
	    "mod_waklog: krb5_get_credentials: %s", krb_err_txt[ kerror ] );
	goto cleanup;
    }

    /* get the V4 credentials */
    if (( kerror = krb524_convert_creds_kdc( kcontext, v5credsp, &v4creds ) ) ) {
	ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
	    "mod_waklog: krb524_convert_creds_kdc: %s", krb_err_txt[ kerror ] );
	goto cleanup;
    }

    /* assemble the token */
    token.kvno = v4creds.kvno;
    token.startTime = v4creds.issue_date;
    token.endTime = v5credsp->times.endtime;
    memmove( &token.sessionKey, v4creds.session, 8 );
    token.ticketLen = v4creds.ticket_st.length ;
    memmove( token.ticket, v4creds.ticket_st.dat, token.ticketLen );

    /* make sure we have to do this */
    if ( child->token.kvno != token.kvno ||
	    child->token.ticketLen != token.ticketLen ||
	    memcmp( &child->token.sessionKey, &token.sessionKey,
		    sizeof( token.sessionKey ) ) ||
	    memcmp( child->token.ticket, token.ticket, token.ticketLen ) ) {

	ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
		"mod_waklog: %s.%s@%s", v4creds.service, v4creds.instance,
		v4creds.realm );
	ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
		"mod_waklog: %d %d %d", v4creds.lifetime, v4creds.kvno,
		v4creds.issue_date );
	ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
		"mod_waklog: %s %s", v4creds.pname, v4creds.pinst );
	ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
		"mod_waklog: %d", v4creds.ticket_st.length );

	/* build the name */
	strcpy( buf, v4creds.pname );
	if ( v4creds.pinst[ 0 ] ) {
		strcat( buf, "." );
		strcat( buf, v4creds.pinst );
	}

	/* assemble the client */
	strncpy( client.name, buf, MAXKTCNAMELEN - 1 );
	strcpy( client.instance, "" );
	strncpy( client.cell, v4creds.realm, MAXKTCNAMELEN - 1 );

	ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
		"mod_waklog: server: name=%s, instance=%s, cell=%s",
		server.name, server.instance, server.cell );

	ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
		"mod_waklog: client: name=%s, instance=%s, cell=%s",
		 client.name, client.instance, client.cell );

	/* use the path */
	krb_set_tkt_string( (char *)k4path );

	/* rumor: we have to do this for AIX 4.1.4 with AFS 3.4+ */
	write( 2, "", 0 );

	if ( ( rc = ktc_SetToken( &server, &token, &client, 0 ) ) ) {
	    ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
		"mod_waklog: settoken returned %d", rc );
	}

	/* save this */
	memmove( &child->token, &token, sizeof( struct ktc_token ) );

	/* we'll need to unlog when this connection is done. */
	ap_register_cleanup( r->pool, (void *)r, token_cleanup, ap_null_cleanup );
    }

cleanup:
    if ( v5credsp )
	krb5_free_cred_contents( kcontext, v5credsp );
    if ( increds.client )
	krb5_free_principal( kcontext, increds.client );
    if ( increds.server )
	krb5_free_principal( kcontext, increds.server );
    if ( kccache )
	krb5_cc_close( kcontext, kccache );
    if ( kcontext )
	krb5_free_context( kcontext );

    ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
	        "mod_waklog: finished with waklog_aklog" );

    return;

}

    static int
waklog_child_routine( void *s, child_info *pinfo )
{
    if ( !getuid() ) {
	ap_log_error( APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, s,
		"mod_waklog: waklog_child_routine called as root" );

	/* this was causing the credential file to get owned by root */
	setgid(ap_group_id);
	setuid(ap_user_id);
    }

    while( 1 ) {
	waklog_kinit( s );
	sleep( 300 /* 10*60*60 - 5*60 */ );
    }

}


    static void
waklog_init( server_rec *s, pool *p )
{
    extern char	*version;
    int pid;

    ap_log_error( APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, s,
	    "mod_waklog: version %s initialized.", version );

    pid = ap_bspawn_child( p, waklog_child_routine, s, kill_always,
	    NULL, NULL, NULL );

    ap_log_error( APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, s,
	    "mod_waklog: ap_bspawn_child: %d.", pid );
}


    static int
waklog_phase0( request_rec *r )
{
    waklog_host_config  *cfg;

    ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
	"mod_waklog: phase0 called" );

    /* directory config? */
    cfg = (waklog_host_config *)ap_get_module_config(
            r->per_dir_config, &waklog_module);

    /* server config? */
    if ( !cfg->configured ) {
	cfg = (waklog_host_config *)ap_get_module_config(
	    r->server->module_config, &waklog_module);
    }

    if ( !cfg->protect ) {
	ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
	    "mod_waklog: phase0 declining" );
        return( DECLINED );
    }

    /* do this only if we are still unauthenticated */
    if ( !child->token.ticketLen ) {

	/* set our environment variables */
	ap_table_set( r->subprocess_env, "KRB5CCNAME", K5PATH );
	ap_table_set( r->subprocess_env, "KRBTKFILE", K4PATH );

	/* stuff the credentials into the kernel */
	waklog_aklog( r );
    }
    
    ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
	"mod_waklog: phase0 returning" );
    return DECLINED;
}


    static int
waklog_phase7( request_rec *r )
{
    waklog_host_config	*cfg;

    ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
	"mod_waklog: phase7 called" );

    /* directory config? */
    cfg = (waklog_host_config *)ap_get_module_config(
            r->per_dir_config, &waklog_module);

    /* server config? */
    if ( !cfg->configured ) {
	cfg = (waklog_host_config *)ap_get_module_config(
	    r->server->module_config, &waklog_module);
    }

    if ( !cfg->protect ) {
        return( DECLINED );
    }

    /* stuff the credentials into the kernel */
    waklog_aklog( r );

    ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
	"mod_waklog: phase7 returning" );

    return DECLINED;
}

    static void
waklog_new_connection( conn_rec *c ) {
    ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, c->server,
	"mod_waklog: new_connection called: conn_rec: 0x%08x pid: %d", c, getpid() );
    return;
}

module MODULE_VAR_EXPORT waklog_module = {
    STANDARD_MODULE_STUFF, 
    waklog_init,              /* module initializer                  */
    waklog_create_dir_config, /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    waklog_create_server_config, /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    waklog_cmds,           /* table of config file commands       */
    NULL,                  /* [#8] MIME-typed-dispatched handlers */
    NULL,                  /* [#1] URI to filename translation    */
    NULL,                  /* [#4] validate user id from request  */
    NULL,                  /* [#5] check if the user is ok _here_ */
    NULL,                  /* [#3] check access by host address   */
    NULL,                  /* [#6] determine MIME type            */
    waklog_phase7,         /* [#7] pre-run fixups                 */
    NULL,                  /* [#9] log a transaction              */
    NULL,                  /* [#2] header parser                  */
    waklog_child_init,     /* child_init                          */
    NULL,                  /* child_exit                          */
    waklog_phase0          /* [#0] post read-request              */
#ifdef EAPI
   ,NULL,                  /* EAPI: add_module                    */
    NULL,                  /* EAPI: remove_module                 */
    NULL,                  /* EAPI: rewrite_command               */
    waklog_new_connection  /* EAPI: new_connection                */
#endif
};
