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

#define KEYTAB			"/home/drh/keytab.umweb.drhtest"
#define KEYTAB_PRINCIPAL	"umweb/drhtest"

#define TKT_LIFE	10*60*60
#define	SLEEP_TIME	5*60 /* should be TKT_LIFE */

#define AFS_CELL	"umich.edu" /* NB: lower case */

#define K5PATH		"FILE:/tmp/waklog.creds.k5"
#define K4PATH		"/tmp/waklog.creds.k4"

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
    char	*afs_cell;
} waklog_host_config;

typedef struct {
	struct ktc_token	token;
} waklog_child_config;
waklog_child_config	child;

void
bin_dump( char *s, char *cp, int count )
{
    char *buffer;
    char c;
    int w;
    int i;
    long o;

    o = 0;
    buffer = cp;
    while ( count > 0 ) {
        c = 16;
        if (c > count) {
	    c = count;
	}
        sprintf( s, "%05lx:", o);
	s += strlen(s);
        w = 0;
        for (i = 0; i < c/2; ++i) {
            w += 5;
            sprintf( s, " %04x", ((unsigned short *)buffer)[i]);
	    s += strlen(s);
	}
        if (c & 1) {
            w += 3;
            sprintf( s, " %02x", buffer[c-1]);
	    s += strlen(s);
	}
        while (w < 41) {
            ++w;
            sprintf( s, "%c", ' ');
	    s += strlen(s);
	}
        for (i = 0; i < c; ++i) {
            if (isprint(buffer[i])) {
                    sprintf( s, "%c", buffer[i]);
            } else {
                    sprintf( s, ".");
	    }
	    s += strlen(s);
	}
        sprintf( s, "\n" );
	s += strlen(s);
        o += c;
        buffer += c;
        count -= c;
    }
    sprintf( s, "%05lx:\0", o );
}


    static void *
waklog_create_dir_config( pool *p, char *path )
{
    waklog_host_config *cfg;

    cfg = (waklog_host_config *)ap_pcalloc( p, sizeof( waklog_host_config ));
    cfg->configured = 0;
    cfg->protect = 0;
    cfg->keytab = KEYTAB;
    cfg->keytab_principal = KEYTAB_PRINCIPAL;
    cfg->afs_cell = AFS_CELL;

    return( cfg );
}


    static void *
waklog_create_server_config( pool *p, server_rec *s )
{
    waklog_host_config *cfg;

    cfg = (waklog_host_config *)ap_pcalloc( p, sizeof( waklog_host_config ));
    cfg->configured = 0;
    cfg->protect = 0;
    cfg->keytab = KEYTAB;
    cfg->keytab_principal = KEYTAB_PRINCIPAL;
    cfg->afs_cell = AFS_CELL;

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


    static const char *
set_waklog_use_keytab_principal( cmd_parms *params, void *mconfig, char *file  )
{
    waklog_host_config          *cfg;

    if ( params->path == NULL ) {
        cfg = (waklog_host_config *) ap_get_module_config(
                params->server->module_config, &waklog_module );
    } else {
        cfg = (waklog_host_config *)mconfig;
    }

    ap_log_error( APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, params->server,
	    "mod_waklog: using keytab_principal: %s", file );

    cfg->keytab_principal = file;
    cfg->configured = 1;
    return( NULL );
}


    static const char *
set_waklog_use_afs_cell( cmd_parms *params, void *mconfig, char *file  )
{
    waklog_host_config          *cfg;

    if ( params->path == NULL ) {
        cfg = (waklog_host_config *) ap_get_module_config(
                params->server->module_config, &waklog_module );
    } else {
        cfg = (waklog_host_config *)mconfig;
    }

    ap_log_error( APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, params->server,
	    "mod_waklog: using afs_cell: %s", file );

    cfg->afs_cell = file;
    cfg->configured = 1;
    return( NULL );
}


    static void
waklog_child_init( server_rec *s, pool *p )
{

    memset( &child.token, 0, sizeof( struct ktc_token ) );

    setpag();

    return;
}


command_rec waklog_cmds[ ] =
{
    { "WaklogProtected", set_waklog_protect,
    NULL, RSRC_CONF | ACCESS_CONF, FLAG,
    "enable waklog on a location or directory basis" },

    { "WaklogUseKeytabPath", set_waklog_use_keytab,
    NULL, RSRC_CONF, TAKE1,
    "Use the supplied keytab rather than the default" },

    { "WaklogUseKeytabPrincipal", set_waklog_use_keytab_principal,
    NULL, RSRC_CONF, TAKE1,
    "Use the supplied keytab principal rather than the default" },

    { "WaklogUseAFSCell", set_waklog_use_afs_cell,
    NULL, RSRC_CONF, TAKE1,
    "Use the supplied AFS cell rather than the default" },

    { NULL }
};


    static void
token_cleanup( void *data )
{
    request_rec		*r = (request_rec *)data;

    if ( child.token.ticketLen ) {
	memset( &child.token, 0, sizeof( struct ktc_token ) );

	ktc_ForgetAllTokens();

	ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
	    "mod_waklog: ktc_ForgetAllTokens succeeded: pid: %d", getpid() );
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
    krb5_ccache			kccache = NULL;
    krb5_keytab			keytab = NULL;
    char			ktbuf[ MAX_KEYTAB_NAME_LEN + 1 ];
    waklog_host_config		*cfg;

    ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, s,
	"mod_waklog: waklog_kinit called" );

    cfg = (waklog_host_config *) ap_get_module_config( s->module_config,
	    &waklog_module );

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

   if (( kerror = krb5_parse_name( kcontext, cfg->keytab_principal, &kprinc ))) {
	ap_log_error( APLOG_MARK, APLOG_ERR, s,
		(char *)error_message( kerror ));

       	goto cleanup;
    }

    krb5_get_init_creds_opt_init( &kopts );
    krb5_get_init_creds_opt_set_tkt_life( &kopts, TKT_LIFE );
    krb5_get_init_creds_opt_set_renew_life( &kopts, 0 );
    krb5_get_init_creds_opt_set_forwardable( &kopts, 1 );
    krb5_get_init_creds_opt_set_proxiable( &kopts, 0 );

    /* keytab from config */
    strncpy( ktbuf, cfg->keytab, sizeof( ktbuf ) - 1 );

    ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, s,
	    "mod_waklog: waklog_kinit using: %s", ktbuf );

    if (( kerror = krb5_kt_resolve( kcontext, ktbuf, &keytab )) != 0 ) {
	ap_log_error( APLOG_MARK, APLOG_ERR, s,
		(char *)error_message( kerror ));

    	goto cleanup;
    }

    /* get the krbtgt */
    if (( kerror = krb5_get_init_creds_keytab( kcontext, &v5creds, 
		kprinc, keytab, 0, NULL, &kopts ))) {

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
    char			buf[ 2048 ];
    const char          	*k4path = NULL;
    const char          	*k5path = NULL;
    krb5_error_code		kerror;
    krb5_context		kcontext = NULL;
    krb5_creds			increds;
    krb5_creds			*v5credsp = NULL;
    krb5_ccache			kccache = NULL;
    struct ktc_principal	server = { "afs", "", "" };
    struct ktc_principal	client;
    struct ktc_token		token;
    waklog_host_config		*cfg;
    int				buflen;

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

    cfg = (waklog_host_config *) ap_get_module_config(
	    r->server->module_config, &waklog_module );

    /* afs/<cell> or afs */
    strncpy( buf, "afs", sizeof( buf ) - 1 );
    if ( strcmp( cfg->afs_cell, AFS_CELL ) ) {
	strncat( buf, "/" ,		sizeof( buf ) - strlen( buf ) - 1 );
	strncat( buf, cfg->afs_cell,	sizeof( buf ) - strlen( buf ) - 1 );
    }

    /* set server part */
    if (( kerror = krb5_parse_name( kcontext, buf, &increds.server ))) {
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
	ap_log_error( APLOG_MARK, APLOG_ERR, r->server,
	    "mod_waklog: krb5_get_credentials: %s", error_message( kerror ));
	goto cleanup;
    }

    /* don't overflor */
    if ( v5credsp->ticket.length >= 344 ) {	/* from krb524d.c */
	ap_log_error( APLOG_MARK, APLOG_ERR, r->server,
	    "mod_waklog: ticket size (%d) to big to fake", v5credsp->ticket.length );
	goto cleanup;
    }

    /* assemble the token */
    memset( &token, 0, sizeof( struct ktc_token ) );

    token.startTime = v5credsp->times.starttime ? v5credsp->times.starttime : v5credsp->times.authtime;
    token.endTime = v5credsp->times.endtime;
    memmove( &token.sessionKey, v5credsp->keyblock.contents,  v5credsp->keyblock.length );
    token.kvno = RXKAD_TKT_TYPE_KERBEROS_V5;
    token.ticketLen = v5credsp->ticket.length;
    memmove( token.ticket, v5credsp->ticket.data, token.ticketLen );

    /*
    ** bin_dump( buf, (char *) &token, token.ticketLen + 24 );
    ** ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
    ** 	"mod_waklog: token\n%s", buf );
    */

    /* make sure we have to do this */
    if ( child.token.kvno != token.kvno ||
	    child.token.ticketLen != token.ticketLen ||
	    (memcmp( &child.token.sessionKey, &token.sessionKey,
		    sizeof( token.sessionKey ) )) ||
	    (memcmp( child.token.ticket, token.ticket, token.ticketLen )) ) {

	/*
	** bin_dump( buf, (char *) &child.token, child.token.ticketLen + 24 );
	** ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
	**	"mod_waklog: child.token\n%s", buf );
	*/

	/* build the name */
	memmove( buf, v5credsp->client->data[0].data, v5credsp->client->data[0].length );
	buf[ v5credsp->client->data[0].length ] = '\0';
	if ( v5credsp->client->length > 1 ) {
		strncat( buf, ".",		sizeof( buf ) - strlen( buf ) - 1 );
		buflen = strlen( buf );
		memmove( buf + buflen, v5credsp->client->data[1].data, v5credsp->client->data[1].length );
		buf[ buflen + v5credsp->client->data[1].length ] = '\0';
	}

	/* assemble the client */
	strncpy( client.name, buf,		sizeof( client.name ) - 1 );
	strncpy( client.instance, "",		sizeof( client.instance) - 1 );
	memmove( buf, v5credsp->client->realm.data, v5credsp->client->realm.length );
 	buf[ v5credsp->client->realm.length ] = '\0';
 	strncpy( client.cell, buf,		sizeof( client.cell ) - 1 );

	/* assemble the server's cell */
	strncpy( server.cell, cfg->afs_cell ,	sizeof( server.cell ) - 1 );

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
	    ap_log_error( APLOG_MARK, APLOG_ERR, r->server,
		"mod_waklog: settoken returned %d", rc );
	    goto cleanup;
	}

	/* save this */
	memmove( &child.token, &token, sizeof( struct ktc_token ) );

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
	sleep( SLEEP_TIME );
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
    if ( !child.token.ticketLen ) {

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
	"mod_waklog: new_connection called: pid: %d", getpid() );
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
