#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include <krb5.h>

#include <sys/ioccom.h>
#include <stropts.h>
#include <kerberosIV/krb.h>
#include <kerberosIV/des.h>
#include <afs/venus.h>

#define KEYTAB_PATH "/usr/local/etc/kerbero/keytab.cosign"
#define IN_TKT_SERVICE "krbtgt/UMICH.EDU"

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
} waklog_host_config;


    static void *
waklog_create_dir_config( pool *p, char *path )
{
    waklog_host_config *cfg;

    cfg = (waklog_host_config *)ap_pcalloc( p, sizeof( waklog_host_config ));
    cfg->configured = 0;
    cfg->protect = 0;
    cfg->keytab = NULL;

    return( cfg );
}


    static void *
waklog_create_server_config( pool *p, server_rec *s )
{
    waklog_host_config *cfg;

    cfg = (waklog_host_config *)ap_pcalloc( p, sizeof( waklog_host_config ));
    cfg->configured = 0;
    cfg->protect = 0;
    cfg->keytab = NULL;

    return( cfg );
}


    static void
waklog_init( server_rec *s, pool *p )
{
    extern char *version;

    ap_log_error( APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, s,
	    "mod_waklog: version %s initialized.", version );
    return;
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

    cfg->keytab = file;
    cfg->configured = 1;
    return( NULL );
}


    static void
waklog_child_init( server_rec *s, pool *p )
{
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
pioctl_cleanup( void *data )
{
    request_rec		*r = (request_rec *)data;
    struct ViceIoctl	vi;

    vi.in = NULL;
    vi.in_size = 0;
    vi.out = NULL;
    vi.out_size = 0;

    if ( pioctl( 0, VIOCUNPAG, &vi, 0 ) < 0 ) {
	ap_log_error( APLOG_MARK, APLOG_ERR, r->server,
		"mod_waklog: unlog pioctl failed" );
    }

    ap_log_error( APLOG_MARK, APLOG_DEBUG, r->server,
	    "mod_waklog: unlog pioctl succeeded" );
    return;
}


    static int
waklog_ktinit( request_rec *r )
{
    krb5_error_code		kerror;
    krb5_context		kcontext;
    krb5_principal		kprinc;
    krb5_principal		sprinc;
    krb5_get_init_creds_opt	kopts;
    krb5_creds			kcreds;
    krb5_ccache			kccache;
    krb5_keytab			keytab = 0;
    char			ktbuf[ MAX_KEYTAB_NAME_LEN + 1 ];
    char               		krbpath [ 24 ];

    if (( kerror = krb5_init_context( &kcontext ))) {
	/* Authentication Required ( kerberos error ) */
	ap_log_error( APLOG_MARK, APLOG_ERR, r->server,
		(char *)error_message( kerror ));

	return;
    }

    if (( kerror = krb5_parse_name( kcontext, r->connection->user,
	    &kprinc ))) {
	ap_log_error( APLOG_MARK, APLOG_ERR, r->server,
		(char *)error_message( kerror ));

	return;
    }

    snprintf( krbpath, sizeof( krbpath ), "/ticket/waklog" );

    if (( kerror = krb5_cc_resolve( kcontext, krbpath, &kccache )) != 0 ) {
	ap_log_error( APLOG_MARK, APLOG_ERR, r->server,
		(char *)error_message( kerror ));

	return;
    }

    krb5_get_init_creds_opt_init( &kopts );
    krb5_get_init_creds_opt_set_tkt_life( &kopts, 10*60*60 );
    krb5_get_init_creds_opt_set_renew_life( &kopts, 0 );
    krb5_get_init_creds_opt_set_forwardable( &kopts, 1 );
    krb5_get_init_creds_opt_set_proxiable( &kopts, 0 );

    if ( KEYTAB_PATH == '\0' ) {
	if (( kerror = krb5_kt_default_name(
		kcontext, ktbuf, MAX_KEYTAB_NAME_LEN )) != 0 ) {
	    ap_log_error( APLOG_MARK, APLOG_ERR, r->server,
		    (char *)error_message( kerror ));

	    return;
	}
    } else {
	if ( strlen( KEYTAB_PATH ) > MAX_KEYTAB_NAME_LEN ) {
	    ap_log_error( APLOG_MARK, APLOG_ERR, r->server,
		    "server configuration error" );

	    return;
	}
	strcpy( ktbuf, KEYTAB_PATH );
    }

    if (( kerror = krb5_kt_resolve( kcontext, ktbuf, &keytab )) != 0 ) {
	ap_log_error( APLOG_MARK, APLOG_ERR, r->server,
		(char *)error_message( kerror ));
	
	return;
    }

    if (( kerror = krb5_sname_to_principal( kcontext, NULL, "cosign",
	    KRB5_NT_SRV_HST, &sprinc )) != 0 ) {
	ap_log_error( APLOG_MARK, APLOG_ERR, r->server,
		(char *)error_message( kerror ));
	
	return;
    }

    if (( kerror = krb5_get_init_creds_keytab( kcontext, &kcreds, 
	    kprinc, keytab, NULL, IN_TKT_SERVICE, &kopts ))) {

	ap_log_error( APLOG_MARK, APLOG_ERR, r->server,
		(char *)error_message( kerror ));

	return;
    }


    (void)krb5_kt_close( kcontext, keytab );
    krb5_free_principal( kcontext, sprinc );

    if (( kerror = krb5_cc_initialize( kcontext, kccache, kprinc )) != 0 ) {
	ap_log_error( APLOG_MARK, APLOG_ERR, r->server,
		(char *)error_message( kerror ));
	
	return;
    }

    if (( kerror = krb5_cc_store_cred( kcontext, kccache, &kcreds )) != 0 ) {
	ap_log_error( APLOG_MARK, APLOG_ERR, r->server,
		(char *)error_message( kerror ));
	
	return;
    }

    krb5_free_cred_contents( kcontext, &kcreds );
    krb5_free_principal( kcontext, kprinc );
    krb5_cc_close( kcontext, kccache );
    krb5_free_context( kcontext );
}


    static int
waklog_get_tokens( request_rec *r )
{
    CREDENTIALS		cr;
    struct ViceIoctl	vi;
    struct ClearToken	ct;
    int			i, rc;
    char		buf[ 1024 ], *s;
    char		*urealm = "UMICH.EDU";
    char		*lrealm = "umich.edu";
    waklog_host_config  *cfg;

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

    if ( cfg->keytab ) {
	ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
		"mod_waklog: keytab is configured: %s", cfg->keytab );

	/* check for afs token? */

	/* authenticate using keytab file */

	/* 524 */

	/* get afs token */

	return OK;
    }

    if (( rc = krb_get_cred( "afs", "", urealm, &cr )) != KSUCCESS ) {
	ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
		"mod_waklog: krb_get_cred: %s", krb_err_txt[ rc ] );

	if (( rc = get_ad_tkt( "afs", "", urealm, 255 )) != KSUCCESS ) {
	    ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r->server,
		    "mod_waklog: get_ad_tkt: %s", krb_err_txt[ rc ] );

	    /* fail here or just let AFS deny permission? */

	    return OK;
	}

	if (( rc = krb_get_cred( "afs", "", urealm, &cr )) != KSUCCESS ) {
	    ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
		    "mod_waklog: krb_get_cred: %s", krb_err_txt[ rc ] );
	    return OK;
	}
    }

    ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r->server,
	    "mod_waklog: %s.%s@%s", cr.service, cr.instance, cr.realm );
    ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r->server,
	    "mod_waklog: %d %d %d", cr.lifetime, cr.kvno, cr.issue_date );
    ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r->server,
	    "mod_waklog: %s %s", cr.pname, cr.pinst );
    ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r->server,
	    "mod_waklog: %d", cr.ticket_st.length );

    s = buf;
    memmove( s, &cr.ticket_st.length, sizeof( int ));
    s += sizeof( int );
    memmove( s, cr.ticket_st.dat, cr.ticket_st.length );
    s += cr.ticket_st.length;

    ct.AuthHandle = cr.kvno;
    memmove( ct.HandShakeKey, cr.session, sizeof( cr.session ));
    ct.ViceId = 0;
    ct.BeginTimestamp = cr.issue_date;
    ct.EndTimestamp = krb_life_to_time( cr.issue_date, cr.lifetime );

    i = sizeof( struct ClearToken );
    memmove( s, &i, sizeof( int ));
    s += sizeof( int );
    memmove( s, &ct, sizeof( struct ClearToken ));
    s += sizeof( struct ClearToken );

    i = 0;
    memmove( s, &i, sizeof( int ));
    s += sizeof( int );

    strcpy( s, lrealm );
    s += strlen( lrealm ) + 1;

    vi.in = buf;
    vi.in_size = s - buf;
    vi.out = buf;
    vi.out_size = sizeof( buf );

    if ( pioctl( 0, VIOCSETTOK, &vi, 0 ) < 0 ) {
	ap_log_error( APLOG_MARK, APLOG_ERR, r->server,
		"mod_waklog: pioctl failed" );
    }

    /* we'll need to unlog when this connection is done. */
    ap_register_cleanup( r->pool, (void *)r, pioctl_cleanup, ap_null_cleanup );

    ap_log_error( APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, r->server,
	    "mod_waklog: finished with get_token" );

    return OK;
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
    waklog_get_tokens,     /* [#7] pre-run fixups                 */
    NULL,                  /* [#9] log a transaction              */
    NULL,                  /* [#2] header parser                  */
    waklog_child_init,     /* child_init                          */
    NULL,                  /* child_exit                          */
    NULL                   /* [#0] post read-request              */
#ifdef EAPI
   ,NULL,                  /* EAPI: add_module                    */
    NULL,                  /* EAPI: remove_module                 */
    NULL,                  /* EAPI: rewrite_command               */
    NULL                   /* EAPI: new_connection                */
#endif
};
