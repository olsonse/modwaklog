#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"

#include <sys/ioccom.h>
#include <stropts.h>
#include <kerberosIV/krb.h>
#include <kerberosIV/des.h>
#include <afs/venus.h>

module waklog_module;

struct ClearToken {
    long AuthHandle;
    char HandShakeKey[ 8 ];
    long ViceId;
    long BeginTimestamp;
    long EndTimestamp;
};

typedef struct {
    int	configured;
    int	protect;
} waklog_host_config;


    static void *
waklog_create_dir_config( pool *p, char *path )
{
    waklog_host_config *cfg;

    cfg = (waklog_host_config *)ap_pcalloc( p, sizeof( waklog_host_config ));
    cfg->configured = 0;
    cfg->protect = 0;

    return( cfg );
}


    static void *
waklog_create_server_config( pool *p, server_rec *s )
{
    waklog_host_config *cfg;

    cfg = (waklog_host_config *)ap_pcalloc( p, sizeof( waklog_host_config ));
    cfg->configured = 0;
    cfg->protect = 0;

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

    ap_log_error( APLOG_MARK, APLOG_ERR, r->server,
	    "mod_waklog: unlog pioctl succeeded" );
    return;
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

    if (( rc = get_ad_tkt( "afs", "", urealm, 255 )) != KSUCCESS ) {
	ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, r->server,
		"mod_waklog: get_ad_tkt: %s", krb_err_txt[ rc ] );

	/* user doesn't have tickets: use server's srvtab */

	return OK;
    }

    if (( rc = krb_get_cred( "afs", "", urealm, &cr )) != KSUCCESS ) {
	ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
		"mod_waklog: krb_get_cred: %s", krb_err_txt[ rc ] );
	return OK;
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

ap_log_error( APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, r->server,
	"mod_waklog: done with token stuff" );

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
