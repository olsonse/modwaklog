#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_core.h"

#ifdef sun
#include <synch.h>
#elif linux
#define use_pthreads
#include <features.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <pthread.h>
#else
#error "make sure you include the right stuff here"
#endif

#ifndef MAXNAMELEN
#define MAXNAMELEN 1024
#endif

#ifdef STANDARD20_MODULE_STUFF
#include <apr_strings.h>
#include <apr_base64.h>
#include <apr_compat.h>
#include <apu_compat.h>

module AP_MODULE_DECLARE_DATA waklog_module;

#define MK_POOL apr_pool_t
#define MK_TABLE_GET apr_table_get
#define MK_TABLE_SET apr_table_set
#include "unixd.h"
extern unixd_config_rec unixd_config;
#define ap_user_id        unixd_config.user_id
#define ap_group_id       unixd_config.group_id
#define ap_user_name      unixd_config.user_name
#define command(name, func, var, type, usage)           \
  AP_INIT_ ## type (name, (void*) func,                 \
        (void*)APR_OFFSETOF(waklog_commands, var),     \
        OR_AUTHCFG | RSRC_CONF, usage)
typedef struct {
       int dummy;
}
child_info;

const char *userdata_key = "waklog_init"; 
#else
#include "ap_config.h"

#define MK_POOL pool
#define MK_TABLE_GET ap_table_get
#define MK_TABLE_SET ap_table_set




#include <krb5.h>

#if defined(sun)
#include <sys/ioccom.h>
#endif /* sun */

#include <stropts.h>
#include <afs/venus.h>
#include <afs/auth.h>
#include <afs/dirpath.h>
#include <afs/ptuser.h>
#include <rx/rxkad.h>

#define TKT_LIFE  ( 12 * 60 * 60 )
#define	SLEEP_TIME	( TKT_LIFE - 5*60 )

#define WAKLOG_ON 1
#define WAKLOG_OFF 2
#define WAKLOG_UNSET 0

#ifdef WAKLOG_DEBUG
#undef APLOG_DEBUG
#define APLOG_DEBUG APLOG_ERR
#endif

#ifndef CELL_IN_PRINCIPAL
int cell_in_principal = 1;
#else
int cell_in_principal = 0;
#endif

/* this is used to turn off pag generation for the backround worker child during startup */
int pag_for_children = 1;

typedef struct
{
  int forked;
  int configured;
  int protect;
  int usertokens;
  char *keytab;
  char *principal;
  char *default_principal;
  char *default_keytab;
  char *afs_cell;
  char *path;
  MK_POOL *p;
}
waklog_config;

typedef struct
{
  struct ktc_token token;
  char clientprincipal[MAXNAMELEN];
  krb5_context kcontext;
  krb5_ccache ccache;
  struct ktc_principal server;
  struct ktc_principal client;
  int pr_init;
} waklog_child_config;

waklog_child_config child;

struct tokencache_ent {
  char clientprincipal[MAXNAMELEN];
  struct ktc_token token;
  struct ktc_principal client;
  struct ktc_principal server;
  time_t lastused;
  int persist;
};

#define SHARED_TABLE_SIZE 512

struct sharedspace_s {
  int renewcount;
  struct tokencache_ent sharedtokens[SHARED_TABLE_SIZE];
};

struct sharedspace_s *sharedspace = NULL;

struct renew_ent {
  char *keytab;
  char *principal;
  int lastrenewed;
};

#ifdef use_pthreads
pthread_rwlock_t *sharedlock = NULL;
#else
rwlock_t *sharedlock = NULL;
#endif

struct renew_ent renewtable[SHARED_TABLE_SIZE];

int renewcount = 0;

module waklog_module;
#define MK_POOL pool
#define MK_TABLE_GET ap_table_get
#define command(name, func, var, type, usage)           \
  { name, func,                                         \
    (void*)XtOffsetOf(waklog_commands, var),           \
    OR_AUTHCFG | RSRC_CONF, type, usage }
#endif /* STANDARD20_MODULE_STUFF */

#define getModConfig(P, X) P = (waklog_config *) ap_get_module_config( (X)->module_config, &waklog_module );

#include <krb5.h>

#if defined(sun)
#include <sys/ioccom.h>
#endif /* sun */
#include <stropts.h>
#include <afs/venus.h>
#include <afs/auth.h>
#include <afs/dirpath.h>
#include <afs/ptuser.h>
#include <rx/rxkad.h>

#define KEYTAB                  "/etc/keytab.wwwserver"
#define PRINCIPAL        "someplacewwwserver"
#define AFS_CELL      "someplace.edu" 

/* If there's an error, retry more aggressively */
#define	ERR_SLEEP_TIME	5*60


#define K5PATH		"FILE:/tmp/waklog.creds.k5"

static void
log_error(const char *file, int line, int level, int status,
           const server_rec *s, const char *fmt, ...)
{
   char errstr[1024];
   va_list ap;

   va_start(ap, fmt);
   vsnprintf(errstr, sizeof(errstr), fmt, ap);
   va_end(ap);

#ifdef STANDARD20_MODULE_STUFF
   ap_log_error(file, line, level | APLOG_NOERRNO, status, s, "%s", errstr);
#else
   ap_log_error(file, line, level | APLOG_NOERRNO, s, "%s", errstr);
#endif

}

    static void *
waklog_create_server_config( MK_POOL *p, server_rec *s )
{
    waklog_config *cfg;

    cfg = (waklog_config *)ap_pcalloc( p, sizeof( waklog_config ));
    cfg->p = p;
    cfg->forked = 0;
    cfg->configured = 0;
    cfg->protect = 0;
    cfg->keytab = KEYTAB;
    cfg->principal = PRINCIPAL;
    cfg->afs_cell = AFS_CELL;

    log_error( APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: server config created." );
    
    return( cfg );
}


    static const char *
set_waklog_protect( cmd_parms *params, void *mconfig, int flag )
{
    waklog_config          *cfg;

    getModConfig(cfg, params->server );

    cfg->protect = flag;
    cfg->configured = 1;
    log_error( APLOG_MARK, APLOG_DEBUG, 0, params->server, "mod_waklog: waklog_protect set" );
    return( NULL );
}


    static const char *
set_waklog_keytab( cmd_parms *params, void *mconfig, char *file  )
{
    waklog_config          *cfg;

    getModConfig(cfg, params->server );

    log_error( APLOG_MARK, APLOG_INFO, 0, params->server,
		"mod_waklog: will use keytab: %s", file );

    cfg->keytab = ap_pstrdup ( params->pool, file );
    cfg->configured = 1;
    return( NULL );
}


    static const char *
set_waklog_use_principal( cmd_parms *params, void *mconfig, char *file  )
{
    waklog_config          *cfg;

    getModConfig(cfg, params->server );

    log_error( APLOG_MARK, APLOG_INFO, 0, params->server,
		"mod_waklog: will use principal: %s", file );

    cfg->principal = ap_pstrdup ( params->pool, file );
    cfg->configured = 1;
    return( NULL );
}


    static const char *
set_waklog_use_afs_cell( cmd_parms *params, void *mconfig, char *file  )
{
    waklog_config          *cfg;

    getModConfig(cfg, params->server );

    log_error( APLOG_MARK, APLOG_INFO, 0, params->server,
		"mod_waklog: will use afs_cell: %s", file );

    cfg->afs_cell = ap_pstrdup( params->pool, file );
    cfg->configured = 1;
    return( NULL );
}


    static void
#ifdef STANDARD20_MODULE_STUFF
waklog_child_init(MK_POOL *p, server_rec *s)
#else 
waklog_child_init(server_rec *s, MK_POOL *p)
#endif
{

    log_error( APLOG_MARK, APLOG_DEBUG, 0, s,
		"mod_waklog: child_init called" );

    memset( &child.token, 0, sizeof( struct ktc_token ) );

    setpag();

    log_error( APLOG_MARK, APLOG_DEBUG, 0, s,
		"mod_waklog: child_init returned" );

    return;
}

typedef struct {
  int wak_protect;
  char *wak_keytab;
  char *wak_ktprinc;
  char *wak_afscell;
} waklog_commands;

command_rec waklog_cmds[ ] =
{
    command("WaklogProtected", set_waklog_protect, wak_protect, FLAG, "enable waklog on a location or directory basis"),

    command("WaklogKeytab", set_waklog_keytab, wak_keytab, TAKE1, "Use the supplied keytab rather than the default"),

    command("WaklogUseKeytabPrincipal", set_waklog_use_principal, wak_ktprinc, TAKE1, "Use the supplied keytab principal rather than the default"),

    command("WaklogUseAFSCell", set_waklog_use_afs_cell, wak_afscell, TAKE1, "Use the supplied AFS cell rather than the default"),

    { NULL }
};


    static int
token_cleanup( void *data )
{
    request_rec		*r = (request_rec *)data;

    if ( child.token.ticketLen ) {
	memset( &child.token, 0, sizeof( struct ktc_token ) );

	ktc_ForgetAllTokens();

	log_error( APLOG_MARK, APLOG_DEBUG, 0, r->server,
		    "mod_waklog: ktc_ForgetAllTokens succeeded: pid: %d", getpid() );
    }
    return 0;
}


    static int
waklog_kinit( server_rec *s )
{
    krb5_error_code		kerror = 0;
    krb5_context		kcontext = NULL;
    krb5_principal		kprinc = NULL;
    krb5_get_init_creds_opt	kopts;
    krb5_creds			v5creds;
    krb5_ccache			kccache = NULL;
    krb5_keytab			keytab = NULL;
    char			ktbuf[ MAX_KEYTAB_NAME_LEN + 1 ];
    int				i;
    waklog_config *cfg;

    log_error( APLOG_MARK, APLOG_DEBUG, 0, s,
		"mod_waklog: waklog_kinit called: pid: %d", getpid() );

    getModConfig(cfg, s);

    if (( kerror = krb5_init_context( &kcontext ))) {
	log_error( APLOG_MARK, APLOG_ERR, 0, s,
		    "mod_waklog: %s", (char *)error_message( kerror ));

        goto cleanup;
    }

    /* use the path */
    if (( kerror = krb5_cc_resolve( kcontext, K5PATH, &kccache )) != 0 ) {
	log_error( APLOG_MARK, APLOG_ERR, 0, s,
		    "mod_waklog: %s", (char *)error_message( kerror ));

    	goto cleanup;
    }

    log_error( APLOG_MARK, APLOG_DEBUG, 0, s,
		"mod_waklog: principal: %s", cfg->principal );

    if (( kerror = krb5_parse_name( kcontext, cfg->principal, &kprinc ))) {
	log_error( APLOG_MARK, APLOG_ERR, 0, s,
		    "mod_waklog: %s", (char *)error_message( kerror ));

       	goto cleanup;
    }

    krb5_get_init_creds_opt_init( &kopts );
    krb5_get_init_creds_opt_set_tkt_life( &kopts, TKT_LIFE );
    krb5_get_init_creds_opt_set_renew_life( &kopts, 0 );
    krb5_get_init_creds_opt_set_forwardable( &kopts, 1 );
    krb5_get_init_creds_opt_set_proxiable( &kopts, 0 );

    /* keytab from config */
    strncpy( ktbuf, cfg->keytab, sizeof( ktbuf ) - 1 );

    log_error( APLOG_MARK, APLOG_DEBUG, 0, s,
		"mod_waklog: waklog_kinit using: %s", ktbuf );

    if (( kerror = krb5_kt_resolve( kcontext, ktbuf, &keytab )) != 0 ) {
	log_error( APLOG_MARK, APLOG_ERR, 0, s,
		    "mod_waklog:krb5_kt_resolve %s", (char *)error_message( kerror ));

    	goto cleanup;
    }

    memset( (char *)&v5creds, 0, sizeof(v5creds));

    /* get the krbtgt */
    if (( kerror = krb5_get_init_creds_keytab( kcontext, &v5creds, 
		kprinc, keytab, 0, NULL, &kopts ))) {

	log_error( APLOG_MARK, APLOG_ERR, 0, s,
		    "mod_waklog:krb5_get_init_creds_keytab %s", (char *)error_message( kerror ));

    	goto cleanup;
    }

    if (( kerror = krb5_cc_initialize( kcontext, kccache, kprinc )) != 0 ) {
	log_error( APLOG_MARK, APLOG_ERR, 0, s,
		    "mod_waklog:krb5_cc_initialize %s", (char *)error_message( kerror ));

    	goto cleanup;
    }

    kerror = krb5_cc_store_cred( kcontext, kccache, &v5creds );
    krb5_free_cred_contents( kcontext, &v5creds );
    if ( kerror != 0 ) {
	log_error( APLOG_MARK, APLOG_ERR, 0, s,
		    "mod_waklog: %s", (char *)error_message( kerror ));

    	goto cleanup;
    }

    log_error( APLOG_MARK, APLOG_DEBUG, 0, s,
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

    log_error( APLOG_MARK, APLOG_DEBUG, 0, s,
		"mod_waklog: waklog_kinit: exiting" );

    return( kerror );
}


    static void
waklog_aklog( request_rec *r )
{
    int				rc;
    char			buf[ MAXKTCTICKETLEN ];
    const char          	*k5path = NULL;
    krb5_error_code		kerror;
    krb5_context		kcontext = NULL;
    krb5_creds			increds;
    krb5_creds			*v5credsp = NULL;
    krb5_ccache			kccache = NULL;
    struct ktc_principal	server = { "afs", "", "" };
    struct ktc_principal	client;
    struct ktc_token		token;
    waklog_config		*cfg;
    int				buflen;

    k5path = MK_TABLE_GET( r->subprocess_env, "KRB5CCNAME" );

    log_error( APLOG_MARK, APLOG_INFO, 0, r->server,
		"mod_waklog: waklog_aklog called: k5path: %s", k5path );

    if ( k5path == NULL ) {
	log_error( APLOG_MARK, APLOG_DEBUG, 0, r->server,
		    "mod_waklog: waklog_aklog giving up" );
	goto cleanup;
    }

    /*
    ** Get/build creds from file/tgs, then see if we need to SetToken
    */

    if (( kerror = krb5_init_context( &kcontext ))) {
	/* Authentication Required ( kerberos error ) */
	log_error( APLOG_MARK, APLOG_ERR, 0, r->server,
		    (char *)error_message( kerror ));
	
	goto cleanup;
    }

    memset( (char *)&increds, 0, sizeof(increds));

    getModConfig(cfg, r->server );

    /* afs/<cell> or afs */
    strncpy( buf, "afs", sizeof( buf ) - 1 );
    if ( strcmp( cfg->afs_cell, AFS_CELL ) ) {
	strncat( buf, "/" ,		sizeof( buf ) - strlen( buf ) - 1 );
	strncat( buf, cfg->afs_cell,	sizeof( buf ) - strlen( buf ) - 1 );
    }

    /* set server part */
    if (( kerror = krb5_parse_name( kcontext, buf, &increds.server ))) {
	log_error( APLOG_MARK, APLOG_ERR, 0, r->server,
		    (char *)error_message( kerror ));

	goto cleanup;
    }

    if (( kerror = krb5_cc_resolve( kcontext, k5path, &kccache )) != 0 ) {
	log_error( APLOG_MARK, APLOG_ERR, 0, r->server,
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
	log_error( APLOG_MARK, APLOG_ERR, 0, r->server,
		    "mod_waklog: krb5_get_credentials: %s", error_message( kerror ));
	goto cleanup;
    }

    /* don't overflow */
    if ( v5credsp->ticket.length >= MAXKTCTICKETLEN ) {	/* from krb524d.c */
	log_error( APLOG_MARK, APLOG_ERR, 0, r->server,
		    "mod_waklog: ticket size (%d) too big to fake", v5credsp->ticket.length );
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

    /* make sure we have to do this */
    if ( child.token.kvno != token.kvno ||
	    child.token.ticketLen != token.ticketLen ||
	    (memcmp( &child.token.sessionKey, &token.sessionKey,
		    sizeof( token.sessionKey ) )) ||
	    (memcmp( child.token.ticket, token.ticket, token.ticketLen )) ) {

	log_error( APLOG_MARK, APLOG_DEBUG, 0, r->server,
		    "mod_waklog: client: %s", buf );

	/* build the name */
	memmove( buf, v5credsp->client->data[0].data,
		min( v5credsp->client->data[0].length, MAXKTCNAMELEN - 1 ) );
	buf[ v5credsp->client->data[0].length ] = '\0';
	if ( v5credsp->client->length > 1 ) {
		strncat( buf, ".", sizeof( buf ) - strlen( buf ) - 1 );
		buflen = strlen( buf );
		memmove( buf + buflen, v5credsp->client->data[1].data,
			min( v5credsp->client->data[1].length, MAXKTCNAMELEN - strlen( buf ) - 1 ) );
		buf[ buflen + v5credsp->client->data[1].length ] = '\0';
	}

	/* assemble the client */
	strncpy( client.name, buf,		sizeof( client.name ) - 1 );
	strncpy( client.instance, "",		sizeof( client.instance) - 1 );
	memmove( buf, v5credsp->client->realm.data, 
		min( v5credsp->client->realm.length, MAXKTCNAMELEN - 1 ) );
 	buf[ v5credsp->client->realm.length ] = '\0';
 	strncpy( client.cell, buf,		sizeof( client.cell ) - 1 );

	/* assemble the server's cell */
	strncpy( server.cell, cfg->afs_cell ,	sizeof( server.cell ) - 1 );

	log_error( APLOG_MARK, APLOG_DEBUG, 0, r->server,
		    "mod_waklog: server: name=%s, instance=%s, cell=%s",
		    server.name, server.instance, server.cell );
	
	log_error( APLOG_MARK, APLOG_DEBUG, 0, r->server,
		    "mod_waklog: client: name=%s, instance=%s, cell=%s",
		    client.name, client.instance, client.cell );

	/* use the path */

	/* rumor: we have to do this for AIX 4.1.4 with AFS 3.4+ */
	write( 2, "", 0 );

	if ( ( rc = ktc_SetToken( &server, &token, &client, 0 ) ) ) {
	    log_error( APLOG_MARK, APLOG_ERR, 0, r->server,
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

    log_error( APLOG_MARK, APLOG_DEBUG, 0, r->server,
	       "mod_waklog: finished with waklog_aklog" );

    return;

}

    static int
waklog_child_routine( void *s, child_info *pinfo )
{
    if ( !getuid() ) {
	log_error( APLOG_MARK, APLOG_DEBUG, 0, s,
		 "mod_waklog: waklog_child_routine called as root" );

	/* this was causing the credential file to get owned by root */
#ifdef STANDARD20_MODULE_STUFF
	setgid(ap_group_id);
	setuid(ap_user_id);
#endif
    }

    while( 1 ) {
	waklog_kinit( s );
	log_error( APLOG_MARK, APLOG_DEBUG, 0, s,
		 "mod_waklog: child_routine sleeping" );
	sleep( SLEEP_TIME );
	log_error( APLOG_MARK, APLOG_DEBUG, 0, s,
		 "mod_waklog: slept, calling waklog_kinit" );
    }

}

#ifdef STANDARD20_MODULE_STUFF
static int
waklog_init_handler(apr_pool_t *p, apr_pool_t *plog,
		    apr_pool_t *ptemp, server_rec *s)
{
    int rv;
    extern char	*version;
    apr_proc_t *proc;
    waklog_config          *cfg;
    void *data;

    getModConfig(cfg, s);

    /* initialize_module() will be called twice, and if it's a DSO
     * then all static data from the first call will be lost. Only
     * set up our static data on the second call. 
     * see http://issues.apache.org/bugzilla/show_bug.cgi?id=37519 */
    apr_pool_userdata_get(&data, userdata_key, s->process->pool);

    if (!data) {
	apr_pool_userdata_set((const void *)1, userdata_key,
			      apr_pool_cleanup_null, s->process->pool);
    } else {
	log_error( APLOG_MARK, APLOG_INFO, 0, s,
		   "mod_waklog: version %s initialized.", version );
	
	proc = (apr_proc_t *)ap_pcalloc( s->process->pool, sizeof(apr_proc_t));
	
	rv = apr_proc_fork(proc, s->process->pool);
	
	if (rv == APR_INCHILD) {
	    waklog_child_routine(s, NULL);
	} else {
	    apr_pool_note_subprocess(s->process->pool, proc, APR_KILL_ALWAYS); 
	}
	/* parent and child */
	cfg->forked = proc->pid;
    }
    return 0;
}
#else
    static void
waklog_init( server_rec *s, MK_POOL *p )
{
    extern char	*version;
    int pid;

    log_error( APLOG_MARK, APLOG_INFO, 0, s,
	       "mod_waklog: version %s initialized.", version );

    pid = ap_bspawn_child( p, waklog_child_routine, s, kill_always,
	    NULL, NULL, NULL );

    log_error( APLOG_MARK, APLOG_DEBUG, 0, s,
	       "mod_waklog: ap_bspawn_child: %d.", pid );
}
#endif

    static int
waklog_phase0( request_rec *r )
{
    waklog_config  *cfg;

    log_error( APLOG_MARK, APLOG_DEBUG, 0, r->server,
	       "mod_waklog: phase0 called" );

    getModConfig(cfg, r->server );

    log_error( APLOG_MARK, APLOG_DEBUG, 0, r->server,
	"mod_waklog: phase0, checking cfg->protect" );
    if ( !cfg->protect ) {
	log_error( APLOG_MARK, APLOG_DEBUG, 0, r->server,
		   "mod_waklog: phase0 declining" );
        return( DECLINED );
    }

    log_error( APLOG_MARK, APLOG_DEBUG, 0, r->server,
	"mod_waklog: phase0, NOT setting environment variable" );
    /* set our environment variable */
    apr_table_set( r->subprocess_env, "KRB5CCNAME", K5PATH );

    log_error( APLOG_MARK, APLOG_DEBUG, 0, r->server,
	"mod_waklog: phase0, checking child.token.ticketLen" );
    /* do this only if we are still unauthenticated */
    if ( !child.token.ticketLen ) {
 
        log_error( APLOG_MARK, APLOG_DEBUG, 0, r->server,
	"mod_waklog: phase0, calling waklog_aklog" );
	/* stuff the credentials into the kernel */
	waklog_aklog( r );
    }
    
    log_error( APLOG_MARK, APLOG_DEBUG, 0, r->server,
	       "mod_waklog: phase0 returning" );
    return DECLINED;
}


    static int
waklog_phase7( request_rec *r )
{
    waklog_config	*cfg;

    log_error( APLOG_MARK, APLOG_DEBUG, 0, r->server,
	       "mod_waklog: phase7 called" );

    getModConfig(cfg, r->server );

    if ( !cfg->protect ) {
        return( DECLINED );
    }

    /* stuff the credentials into the kernel */

    log_error( APLOG_MARK, APLOG_DEBUG, 0, r->server,
	"mod_waklog: phase7, calling waklog_aklog" );
    waklog_aklog( r );

    log_error( APLOG_MARK, APLOG_DEBUG, 0, r->server,
	       "mod_waklog: phase7 returning" );

    return DECLINED;
}


static
#ifdef STANDARD20_MODULE_STUFF
  int
#else
  void
#endif
waklog_new_connection (conn_rec * c
#ifdef STANDARD20_MODULE_STUFF
		       , void *dummy
#endif
  )
{
  
  waklog_commands *cfg;
  
  log_error (APLOG_MARK, APLOG_DEBUG, 0, c->base_server,
	     "mod_waklog: new_connection called: pid: %d", getpid ());
  /*	
	getModConfig(cfg, c->base_server);
	
	if ( cfg->default_principal ) {
	  log_error(APLOG_MARK, APLOG_DEBUG, 0, c->base_server, "mod_waklog: new conn setting default user %s",
	  cfg->default_principal);
	  set_auth( c->base_server, NULL, 0, cfg->default_principal, cfg->default_keytab, 0);
	}     
  */     
	     
    return
#ifdef STANDARD20_MODULE_STUFF
      0
#endif
      ;
}


/*
**  Here's a quick explaination for phase0 and phase2:
**  Apache does a stat() on the path between phase0 and
**  phase2, and must by ACLed rl to succeed.  So, at
**  phase0 we acquire credentials for umweb:servers from
**  a keytab, and at phase2 we must ensure we remove them.
**
**  Failure to "unlog" would be a security risk.
*/
static int
waklog_phase2 (request_rec * r)
{

  log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server,
	     "mod_waklog: phase2 called");

  if (child.token.ticketLen)
    {
      memset (&child.token, 0, sizeof (struct ktc_token));

      ktc_ForgetAllTokens ();

      log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server,
		 "mod_waklog: ktc_ForgetAllTokens succeeded: pid: %d",
		 getpid ());
    }

  log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server,
	     "mod_waklog: phase2 returning");

    return DECLINED;
}

#ifndef STANDARD20_MODULE_STUFF
module MODULE_VAR_EXPORT waklog_module = {
    STANDARD_MODULE_STUFF, 
    waklog_init,           /* module initializer                  */
#if 0
    waklog_create_dir_config, /* create per-dir    config structures */
#else /* 0 */
    NULL,                  /* create per-dir    config structures */
#endif /* 0 */
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
    waklog_phase2,         /* [#2] header parser                  */
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
#else
static void
waklog_register_hooks (apr_pool_t * p)
{
    ap_hook_header_parser (waklog_phase2, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_fixups (waklog_phase7, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_child_init (waklog_child_init, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_post_read_request (waklog_phase0, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_pre_connection (waklog_new_connection, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_post_config (waklog_init_handler, NULL, NULL, APR_HOOK_MIDDLE);
}


module AP_MODULE_DECLARE_DATA waklog_module =
{
   STANDARD20_MODULE_STUFF,
   NULL,                        /* create per-dir    conf structures  */
   NULL,                        /* merge  per-dir    conf structures  */
   waklog_create_server_config, /* create per-server conf structures  */
   NULL,                        /* merge  per-server conf structures  */
   waklog_cmds,                 /* table of configuration directives  */
   waklog_register_hooks          /* register hooks                     */
};
#endif

