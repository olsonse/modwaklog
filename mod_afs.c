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

#define SRVTAB "/usr/local/etc/srvtab.itdwww"

struct ClearToken {
    long AuthHandle;
    char HandShakeKey[ 8 ];
    long ViceId;
    long BeginTimestamp;
    long EndTimestamp;
};

    static void
afs_init( server_rec *s, pool *p )
{
    extern char *version;

    ap_log_error( APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, s,
	    "mod_afs: version %s initialized.", version );
    return;
}


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
		"unlog pioctl failed\n" );
    }

    ap_log_error( APLOG_MARK, APLOG_ERR, r->server,
	    "unlog pioctl succeeded\n" );
}


    static int
get_afs_tokens( request_rec *r )
{
    CREDENTIALS		cr;
    struct ViceIoctl	vi;
    struct ClearToken	ct;
    int			i, rc;
    char		buf[ 1024 ], *s;
    char		*urealm = "UMICH.EDU";
    char		*lrealm = "umich.edu";

    setpag();

    if (( rc = get_ad_tkt( "afs", "", urealm, 255 )) != KSUCCESS ) {
	ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, r->server,
		"get_ad_tkt: %s\n", krb_err_txt[ rc ] );

	/* user doesn't have tickets: use server's srvtab */

	return OK;
    }

    if (( rc = krb_get_cred( "afs", "", urealm, &cr )) != KSUCCESS ) {
	ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
		"krb_get_cred: %s\n", krb_err_txt[ rc ] );
	return OK;
    }

    ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r->server,
	    "%s.%s@%s\n", cr.service, cr.instance, cr.realm );
    ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r->server,
	    "%d %d %d\n", cr.lifetime, cr.kvno, cr.issue_date );
    ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r->server,
	    "%s %s\n", cr.pname, cr.pinst );
    ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r->server,
	    "%d\n", cr.ticket_st.length );

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
		"pioctl failed\n" );
    }

    /* we'll need to unlog when this connection is done. */
    ap_register_cleanup( r->pool, (void *)r, pioctl_cleanup, ap_null_cleanup );

ap_log_error( APLOG_MARK, APLOG_ERR, r->server, "done with token stuff\n" );

    return OK;
}


module MODULE_VAR_EXPORT afs_module = {
    STANDARD_MODULE_STUFF, 
    afs_init,              /* module initializer                  */
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    NULL,                  /* table of config file commands       */
    NULL,                  /* [#8] MIME-typed-dispatched handlers */
    NULL,                  /* [#1] URI to filename translation    */
    NULL,                  /* [#4] validate user id from request  */
    NULL,                  /* [#5] check if the user is ok _here_ */
    NULL,                  /* [#3] check access by host address   */
    NULL,                  /* [#6] determine MIME type            */
    NULL,                  /* [#7] pre-run fixups                 */
    NULL,                  /* [#9] log a transaction              */
    get_afs_tokens,        /* [#2] header parser                  */
    NULL,                  /* child_init                          */
    NULL,                  /* child_exit                          */
    NULL                   /* [#0] post read-request              */
#ifdef EAPI
   ,NULL,                  /* EAPI: add_module                    */
    NULL,                  /* EAPI: remove_module                 */
    NULL,                  /* EAPI: rewrite_command               */
    NULL                   /* EAPI: new_connection                */
#endif
};
