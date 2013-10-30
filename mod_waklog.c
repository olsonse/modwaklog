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
#include <stropts.h>
#include <sys/ioccom.h>
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
#define APACHE2
#endif

/********************* APACHE1 ******************************************************************************/
#ifndef APACHE2
#include "ap_config.h"
#include <http_conf_globals.h>
#define MK_POOL pool
#define MK_TABLE_GET ap_table_get
#define MK_TABLE_SET ap_table_set
#define command(name, func, var, type, usage) \
  { name, func, \
    NULL , \
    RSRC_CONF | ACCESS_CONF , type, usage }
module waklog_module;

/********************* APACHE2 ******************************************************************************/
#else
#include "http_connection.h"
#include <apr_strings.h>
#include <apr_base64.h>
#define ap_pcalloc apr_pcalloc
#define ap_pdupstr apr_pdupstr
#define ap_pstrdup apr_pstrdup
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
        NULL,     \
        RSRC_CONF | ACCESS_CONF, usage)
module AP_MODULE_DECLARE_DATA waklog_module;
typedef struct { int dummy; } child_info;
const char *userdata_key = "waklog_init"; 

#endif /* APACHE2 */
/**************************************************************************************************/

#include <krb5.h>
#include <kopenafs.h>

#include <afs/param.h>

#include <afs/venus.h>
#include <afs/auth.h>
#include <afs/dirpath.h>
#include <afs/ptuser.h>
#include <rx/rxkad.h>

#define TKT_LIFE  ( 12 * 60 * 60 )
#define SLEEP_TIME      ( TKT_LIFE - 5*60 )

#define WAKLOG_UNSET -1

#ifdef WAKLOG_DEBUG
#undef APLOG_DEBUG
#define APLOG_DEBUG APLOG_ERR
#endif

/* this is used to turn off pag generation for the backround worker child during startup */
int pag_for_children = 1;

typedef struct
{
  int forked;
  int configured;
  int protect;
  int usertokens;
  int cell_in_principal;
  int disable_token_cache;
  char *keytab;
  char *principal;
  char *default_principal;
  char *default_keytab;
  char *afs_cell;
  char *afs_cell_realm;
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



#define getModConfig(P, X) P = (waklog_config *) ap_get_module_config( (X)->module_config, &waklog_module );


static void
log_error (const char *file, int line, int level, int status,
           const server_rec * s, const char *fmt, ...)
{
  char errstr[4096];
  va_list ap;

  va_start (ap, fmt);
  vsnprintf (errstr, 1024, fmt, ap);
  va_end (ap);

#ifdef APACHE2
  ap_log_error (file, line, level | APLOG_NOERRNO, status, s, "(%d) %s", getpid(), errstr);
#else
  ap_log_error (file, line, level | APLOG_NOERRNO, s, "(%d) %s", getpid(), errstr);
#endif

}

waklog_config *retrieve_config(request_rec *r) {
  
  request_rec *my;
  waklog_config *cfg;
  
  if ( r && r->main ) {
    my = r->main;
  } else if (r) {
    my = r;
  } else {
    return NULL;
  }
  
  if ( my && ( cfg = (waklog_config *) ap_get_module_config(my->per_dir_config, &waklog_module ) ) ) {
      return cfg;
  } else {
    getModConfig (cfg, r->server);
  }
  
  return cfg;
  
}

/* set_auth -- sets the tokens of the current process to this user.
  if "self" is set, it divines the user from the current requests' environment.
  otherwise, it's gettng it from principal/keytab */
  
int
set_auth ( server_rec *s, request_rec *r, int self, char *principal, char *keytab, int storeonly ) {
  
  int i;
  int usecached = 0;  
  krb5_error_code kerror = 0;
  krb5_principal kprinc = NULL;
  krb5_get_init_creds_opt kopts;
  krb5_creds v5creds;
  krb5_creds increds;
  krb5_ccache clientccache;
  struct ktc_principal server = { "afs", "", "" };
  struct ktc_principal client;
  struct ktc_token token;
  krb5_creds *v5credsp = NULL;
  krb5_keytab krb5kt = NULL;
  char buf[MAXNAMELEN];
  waklog_config *cfg;
  int rc = 0;
  int buflen = 0;
  time_t oldest_time = 0;
  int oldest = 0;
  int stored = -1;
  time_t mytime;
  int indentical;
  int cell_in_principal;
  int attempt;
  int use_client_credentials = 0;
  
  char k5user[MAXNAMELEN] = "";
  char *k5secret = NULL;

  char *k5path = NULL;
  
  memset((char *) &increds, 0, sizeof(increds));
  /* init some stuff if it ain't already */
  /* XXX - In what situation will these not be initialized? */

  if ( ! child.kcontext ) {
    if ((kerror = krb5_init_context(&child.kcontext))) {
      log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: can't initialize Kerberos context err=%d", 
		kerror);
      return(-1);
    }
  }

  if ( !child.ccache) {
    if ((kerror = krb5_cc_resolve(child.kcontext, "MEMORY:tmpcache", &child.ccache))) {
      log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: can't initialize credentials cache %s err=%d",
                k5path, kerror );
      return(-1);
    }
  }
  
  log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: set_auth: %d, %s, %s, %d, KRB5CC=%s user=%s",
            self, principal ? principal : "NULL", 
            keytab ? keytab : "NULL",
            storeonly,
            k5path ? k5path : "NULL",
#ifdef APACHE2
            (r && r->user) ? r->user : "NULL"
#else
            (r && r->connection && r->connection->user) ? r->connection->user : "NULL"
#endif
            );
  
  /* pull the server config record that we care about... */
  
  if ( r ) {
    cfg = retrieve_config(r);
  } else {
    log_error (APLOG_MARK, APLOG_DEBUG, 0, s,
                 "mod_waklog: set_auth using no config" );
     getModConfig (cfg, s);
  }
  
  if ( ! cfg ) {
    log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: cfg is %d", cfg );
  }


  if ( self ) {
    /* pull out our principal name and stuff from the environment -- webauth better have sent
       through. */

#ifdef APACHE2       
       if ( ! ( r && r->connection && r->user )) {
         log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: self authentication selected, but no data available");
         log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: r->user=%s", (r->user==NULL ? "null" : r->user));
         return -1;
       }
       
       strncpy(k5user, r->user, sizeof(k5user));
#else
       if ( ! (r && r->connection && r->connection->user)) {
	 log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: self authentication selected, but no username available");
         return -1;
       }

       strncpy(k5user, r->connection->user, sizeof(k5user));
#endif
       /* if they've supplied a credentials cache */
       k5path = (char *) MK_TABLE_GET( r->subprocess_env, "KRB5CCNAME" );

       /* the other thing we need is someone's password */       
       k5secret = (char *) MK_TABLE_GET( r->notes, "ATTR_PASSWORD" );
       
       /* we'll pick this up later after we've checked the cache and current state */
             
  } else
  if ( principal ) {
    strncpy(k5user, principal, sizeof(k5user));
  } else
#ifdef APACHE2
  if (r && r->user) {
    strncpy(k5user, r->user, sizeof(k5user));
  }
#else
  if (r && r->connection && r->connection->user) {
    strncpy(k5user, r->connection->user, sizeof(k5user));
  }
#endif
  
  log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: set_auth: k5user=%s", k5user);
  mytime = time(0);
  
  /* see if we should just go ahead and ignore this call, since we already should be set to these
     credentials */

  if ( ! storeonly ) {

#ifdef use_pthreads
    pthread_rwlock_rdlock( sharedlock );
#else
    rw_rdlock( sharedlock );
#endif

    for ( i = 0; i < SHARED_TABLE_SIZE; ++i ) {
    
      /* if it's a token for the principal we're looking for, and it hasn't expired yet */
    
      if ( ( !strcmp( k5user,
                      sharedspace->sharedtokens[i].clientprincipal )  ) && 
                      ( sharedspace->sharedtokens[i].token.endTime > mytime ) ) {             
  
        if ( ! memcmp(&child.token, &sharedspace->sharedtokens[i].token, sizeof(child.token) ) ) {
          indentical = 1;
        } else {
          indentical = 0;
        }
      
        /* copy the token out of the cache and into the child object */
      
        strcpy(child.clientprincipal, sharedspace->sharedtokens[i].clientprincipal );
        memcpy(&child.token, &sharedspace->sharedtokens[i].token, sizeof(child.token));
        memcpy(&child.server, &sharedspace->sharedtokens[i].server, sizeof(child.server));
        memcpy(&child.client, &sharedspace->sharedtokens[i].client, sizeof(child.client));
      
        /* set our last used time thing */
        sharedspace->sharedtokens[i].lastused = mytime;
      
        usecached = 1;      
      
        break;
    
      }
  
    } 
  
    /* release the lock on the token cache */
#ifdef use_pthreads
    pthread_rwlock_unlock( sharedlock );
#else
    rw_unlock( sharedlock );
#endif

    if ( usecached ) {
      /* release the lock on the token cache */
      log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                "mod_waklog: set_auth using shared token %d for %s", i, k5user ); 
    
    }
  
    /* if this is something that was in the cache, and it's the same as the token we already have stored,
      and we weren't calling this just to renew it... */
  
    if ( usecached && indentical ) {
      log_error (APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: token is identical for %s", k5user );
      return 0;
    }
  
  }

  /* if 'usecached' isn't set, we've got to get our tokens from somewhere... */
  if ( ! usecached ) {

    /* clear out the creds structure */
    memset((void *) &v5creds, 0, sizeof(v5creds));
    
    /* create a principal out of our k5user string */
    
    if ( ( kerror = krb5_parse_name (child.kcontext, k5user, &kprinc ) ) ) {
      log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: krb5_parse_name %s", (char *) error_message(kerror) );
      goto cleanup;
    }
    
    /* create the credentials options */
    
    krb5_get_init_creds_opt_init ( &kopts );
    krb5_get_init_creds_opt_set_tkt_life ( &kopts, TKT_LIFE );
    krb5_get_init_creds_opt_set_renew_life ( &kopts, 0 );
    krb5_get_init_creds_opt_set_forwardable ( &kopts, 0 );
    krb5_get_init_creds_opt_set_proxiable ( &kopts, 0 );
    
    if ( keytab || k5secret ) {
    
      if (keytab) {
        /* if we've been passed a keytab, we're going to be getting our credentials from it */
    
        log_error( APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: using keytab %s", keytab);
    
        if ( ( kerror = krb5_kt_resolve(child.kcontext, keytab, &krb5kt ) ) ) {
          log_error( APLOG_MARK, APLOG_ERR, 0, s,
            "mod_waklog: krb5_kt_resolve %s", error_message(kerror) );
          goto cleanup;
        }
    
        if ((kerror = krb5_get_init_creds_keytab (child.kcontext, &v5creds,
              kprinc, krb5kt, 0, NULL, &kopts ) ) ) {
                log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: krb5_get_init_creds_keytab %s",
                  error_message(kerror) );
                goto cleanup;
        }
      } else if (k5secret) {
      
        /* If the WebSSO is lame enough to provide a secret, then try and use that to get a token */
      
        if ((kerror = krb5_get_init_creds_password ( child.kcontext, &v5creds,
              kprinc, k5secret, NULL, NULL, 0, NULL, &kopts ) ) ) {
                log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: krb5_get_init_creds_password %s",
                  error_message(kerror) );
                  /* nuke the password so it doesn't end up in core files */
                  memset(k5secret, 0, sizeof(k5secret));               
                goto cleanup;
        }
      
        memset(k5secret, 0, sizeof(k5secret));      
      }

      /* initialize the credentials cache and store the stuff we just got */
      if ( ( kerror = krb5_cc_initialize (child.kcontext, child.ccache, kprinc) ) ) {
        log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: init credentials cache %s", 
                  error_message(kerror));
        goto cleanup;
      }
      
      if ( ( kerror = krb5_cc_store_cred(child.kcontext, child.ccache, &v5creds) ) ) {
        log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: cannot store credentials %s", 
                  error_message(kerror));
        goto cleanup;
      }
    
      krb5_free_cred_contents(child.kcontext, &v5creds);
 
      if ( kerror ) {
        log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: store cred %s", error_message(kerror));
        goto cleanup;
      }
      
      log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: kinit ok for %s", k5user );

    } else if (k5path) {
      /* If we've got a path to a credentials cache, then try and use that. We can't just
       * replace child.creds, because we want to ensure that only this request gets access to
       * that cache */

      if ( ( kerror = krb5_cc_resolve(child.kcontext, k5path, &clientccache ) ) ) {
        log_error(APLOG_MARK, APLOG_ERR, 0, s,
		  "mod_waklog: can't open provided credentials cache %s err=%d",
		  k5path, kerror );
        goto cleanup;
      }

      use_client_credentials = 1;
    } 
    
    /* now, to the 'aklog' portion of our program. */
    
    /** we make two attempts here, one for afs@REALM and one for afs/cell@REALM */
    for(attempt = 0; attempt <= 1; attempt++) {
      strncpy( buf, "afs", sizeof(buf) - 1 );
      cell_in_principal = (cfg->cell_in_principal + attempt) % 2;

      log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: cell_in_principal=%d", cell_in_principal );
      if (cell_in_principal) {
        strncat(buf, "/",           sizeof(buf) - strlen(buf) - 1);
        strncat(buf, cfg->afs_cell, sizeof(buf) - strlen(buf) - 1);
      }
      if (cfg->afs_cell_realm != NULL) {
        strncat(buf, "@",                 sizeof(buf) - strlen(buf) - 1);
        strncat(buf, cfg->afs_cell_realm, sizeof(buf) - strlen(buf) - 1);
      }
      
      log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: using AFS principal: %s", buf);
      
      if ((kerror = krb5_parse_name (child.kcontext, buf, &increds.server))) {
        log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: krb5_parse name %s", error_message(kerror));
        goto cleanup;
      }

      if (!use_client_credentials) {
        clientccache = child.ccache;
      }

      if ((kerror = krb5_cc_get_principal(child.kcontext, clientccache, &increds.client))) {
        log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: krb5_cc_get_princ %s %p", error_message(kerror), clientccache);
        goto cleanup;
      }
      
      log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: retrieved data from ccache for %s", k5user);
      
      increds.times.endtime = 0;
      
      increds.keyblock.enctype = ENCTYPE_DES_CBC_CRC;
      
      if ( ( kerror = krb5_get_credentials (child.kcontext, 0, clientccache, &increds, &v5credsp ) ) ) {
        /* only complain once we've tried both afs@REALM and afs/cell@REALM */
        if (attempt>=1) {
          log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: krb5_get_credentials: %s",
                    error_message(kerror));
          goto cleanup;
        } else {
          continue;
        }
      }
      cfg->cell_in_principal = cell_in_principal;
      break;
    }

    log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: get_credentials passed for %s", k5user);
    
    if ( v5credsp->ticket.length >= MAXKTCTICKETLEN ) {
      log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: ticket size (%d) too big to fake", 
      v5credsp->ticket.length);
      goto cleanup;
    }

    memset(&token, 0, sizeof(struct ktc_token));
    
    token.startTime = v5credsp->times.starttime ? v5credsp->times.starttime : v5credsp->times.authtime;
    token.endTime = v5credsp->times.endtime;
    
    memmove( &token.sessionKey, v5credsp->keyblock.contents, v5credsp->keyblock.length);
    token.kvno = RXKAD_TKT_TYPE_KERBEROS_V5;
    token.ticketLen = v5credsp->ticket.length;
    memmove( token.ticket, v5credsp->ticket.data, token.ticketLen);
    
    /* build the name */
    
    memmove( buf, v5credsp->client->data[0].data, min(v5credsp->client->data[0].length,
      MAXKTCNAMELEN -1 ));
    buf[v5credsp->client->data[0].length] = '\0';
    if ( v5credsp->client->length > 1 ) {
      strncat(buf, ".", sizeof(buf) - strlen(buf) - 1);
      buflen = strlen(buf);
      memmove(buf + buflen, v5credsp->client->data[1].data,
        min(v5credsp->client->data[1].length,
          MAXKTCNAMELEN - strlen(buf) - 1));
      buf[buflen + v5credsp->client->data[1].length] = '\0';
    }
    
    /* assemble the client */
    strncpy(client.name, buf, sizeof(client.name) - 1 );
    strncpy(client.instance, "", sizeof(client.instance) - 1 );
    memmove(buf, v5credsp->client->realm.data, min(v5credsp->client->realm.length,
            MAXKTCNAMELEN - 1));
    buf[v5credsp->client->realm.length] = '\0';
    strncpy(client.cell, buf, sizeof(client.cell));
    
    /* assemble the server's cell */
    strncpy(server.cell, cfg->afs_cell, sizeof(server.cell) - 1);
    
    log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: preparing to init PTS connection for %s", server.cell);
    
    /* fill out the AFS ID in the client name */
    /* we've done a pr_Initialize in the child_init -- once, per process.  If you try to do it more
     * strange things seem to happen. */
     
     {
      afs_int32 viceId = 0;
 
      log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: making PTS call to look up %s", client.name);
      
      if ( ( rc = pr_SNameToId( client.name, &viceId ) ) == 0 ) {
        snprintf( client.name, sizeof(client.name), "AFS ID %d", viceId );
      } else {
        log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: PTS call returned error %d ", rc);
      }
            
      log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: PTS call returned %s ", client.name);
      
     }
    
    log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: server: name %s, instance %s, cell %s",
      server.name, server.instance, server.cell );
      
    log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: client: name %s, instance %s, cell %s",
      client.name, client.instance, client.cell );
  
    /* copy the resulting stuff into the child structure */
  
    strncpy(child.clientprincipal, k5user, sizeof(child.clientprincipal));
    memcpy(&child.token, &token, sizeof(child.token));
    memcpy(&child.server, &server, sizeof(child.server));
    memcpy(&child.client, &client, sizeof(child.client));
  
    /* stuff the resulting token-related stuff into our shared token cache */
    /* note, that anything that was set from a keytab is "persistant", and is immune
     * from LRU-aging.  This is because nothing but the process that's running as root
     * can update these, and it's running every hour or so and renewing these tokens.
     * and we don't want them aged out.
     */
     
    mytime = oldest_time = time(0);
    
    log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: waiting for shared space for %s ", k5user);

#ifdef use_pthreads
    pthread_rwlock_wrlock(sharedlock);
#else
    rw_wrlock(sharedlock);
#endif

    for( i = ( SHARED_TABLE_SIZE - 1 ); i >= 0; i-- ) {
      if ( ( sharedspace->sharedtokens[i].lastused <= oldest_time) && 
           ( sharedspace->sharedtokens[i].persist == 0 ) ) {
        oldest = i;
        oldest_time = sharedspace->sharedtokens[i].lastused;
      }      
      if ( ! strcmp ( sharedspace->sharedtokens[i].clientprincipal,
                      child.clientprincipal ) ) {
        memcpy(&sharedspace->sharedtokens[i].token, &child.token, sizeof(child.token) );
        memcpy(&sharedspace->sharedtokens[i].client, &child.client, sizeof(child.client) );
        memcpy(&sharedspace->sharedtokens[i].server, &child.server, sizeof(child.server) );
        sharedspace->sharedtokens[i].lastused = mytime;
        sharedspace->sharedtokens[i].persist = keytab ? 1 : 0;
        stored = i;
        break;
      }
    }
    
    if ( stored == -1 ) {
      memcpy(&sharedspace->sharedtokens[oldest].token, &child.token, sizeof(child.token) );
      memcpy(&sharedspace->sharedtokens[oldest].client, &child.client, sizeof(child.client) );
      memcpy(&sharedspace->sharedtokens[oldest].server, &child.server, sizeof(child.server) );
      strcpy(sharedspace->sharedtokens[oldest].clientprincipal, child.clientprincipal );
      sharedspace->sharedtokens[oldest].lastused = mytime;
      sharedspace->sharedtokens[oldest].persist = keytab ? 1 : 0;
      stored = oldest;
    }

#ifdef use_pthreads
    pthread_rwlock_unlock(sharedlock);
#else
    rw_unlock(sharedlock);
#endif

    log_error( APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: token stored in slot %d for %s", stored,
      child.clientprincipal );
    
  } else if ( ! usecached ) {
    log_error( APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: set_auth divergent case");
  }
  
  if ( storeonly ) {
    goto cleanup;
  }
  
  usecachedtoken:
  
  /* don't ask.  Something about AIX.  We're leaving it here.*/
  /* write(2, "", 0); */
  
  /* we try twice, because sometimes the first one fails.  Dunno why, but it always works the second time */
  
  if ((rc = ktc_SetToken(&child.server, &child.token, &child.client, 0))) {
    log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: settoken returned %s for %s -- trying again", 
      error_message(rc), k5user);
    if ((rc = ktc_SetToken(&child.server, &child.token, &child.client, 0))) {
      log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: settoken2 returned %s for %s", 
        error_message(rc), k5user);
      goto cleanup;
    }
  }
  
  cleanup:
  if (use_client_credentials)
    krb5_cc_close(child.kcontext, clientccache);
  if ( v5credsp )
    krb5_free_cred_contents(child.kcontext, v5credsp);
  if ( increds.client )
    krb5_free_principal (child.kcontext, increds.client);
  if ( increds.server )
    krb5_free_principal (child.kcontext, increds.server);
  if ( krb5kt ) 
    (void) krb5_kt_close(child.kcontext, krb5kt);
  if ( kprinc )
    krb5_free_principal (child.kcontext, kprinc);
  
  if ( rc ) {
    log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: set_auth ending with %d", rc );
  } else if ( kerror ) {
    log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: set_auth ending with krb5 error %d, %s", kerror, error_message(kerror));
  } else {
    log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: set_auth ending ok");
  }
  
  return kerror ? (int) kerror : (int) rc;
  
}


int get_cfg_usertokens(waklog_config *cfg)
{
  if (cfg->usertokens==WAKLOG_UNSET)
    return 0; /* default */
  return cfg->usertokens;
}

int get_cfg_protect(waklog_config *cfg)
{
  if (cfg->protect==WAKLOG_UNSET)
    return 0; /* default */
  return cfg->protect;
}

int get_cfg_disable_token_cache(waklog_config *cfg)
{
  if (cfg->disable_token_cache==WAKLOG_UNSET)
    return 0; /* default */
  return cfg->disable_token_cache;
}


static void *
waklog_create_server_config (MK_POOL * p, server_rec * s)
{
  waklog_config *cfg;

  cfg = (waklog_config *) ap_pcalloc (p, sizeof (waklog_config));
  cfg->p = p;
  memset(cfg, 0, sizeof(waklog_config));
  cfg->path = "(server)";
  cfg->protect = WAKLOG_UNSET;
  cfg->usertokens = WAKLOG_UNSET;
  cfg->disable_token_cache = WAKLOG_UNSET;
  cfg->keytab = NULL;
  cfg->principal = NULL;
  cfg->default_principal = NULL;
  cfg->default_keytab = NULL;
  cfg->afs_cell = NULL;
  cfg->afs_cell_realm = NULL;
  cfg->forked = 0;
  cfg->configured = 0;

  log_error (APLOG_MARK, APLOG_DEBUG, 0, s,
             "mod_waklog: server config created.");

  return (cfg);
}

/* initialize with host-config information */

static void *
waklog_create_dir_config (MK_POOL * p, char *dir)
{
  waklog_config *cfg;

  cfg = (waklog_config *) ap_pcalloc (p, sizeof (waklog_config));
  memset(cfg, 0, sizeof(waklog_config));
  cfg->p = p;
  cfg->path = ap_pstrdup(p, dir );
  cfg->protect = WAKLOG_UNSET;
  cfg->usertokens = WAKLOG_UNSET;
  cfg->disable_token_cache = WAKLOG_UNSET;
  cfg->keytab = NULL;
  cfg->principal = NULL;
  cfg->default_principal = NULL;
  cfg->default_keytab = NULL;
  cfg->afs_cell = NULL;
  cfg->afs_cell_realm = NULL;
  cfg->forked = 0;
  cfg->configured = 0;

  return (cfg);
}

static void *waklog_merge_dir_config(MK_POOL *p, void *parent_conf, void *newloc_conf) {

  waklog_config *merged = ( waklog_config * ) ap_pcalloc(p, sizeof(waklog_config ) );
  waklog_config *parent = ( waklog_config * ) parent_conf;
  waklog_config *child = ( waklog_config * ) newloc_conf;
  
  merged->protect = child->protect != WAKLOG_UNSET ? child->protect : parent->protect;
  
  merged->path = child->path != NULL ? child->path : parent->path;
  
  merged->usertokens = child->usertokens != WAKLOG_UNSET ? child->usertokens : parent->usertokens;

  merged->disable_token_cache = child->disable_token_cache != WAKLOG_UNSET ? child->disable_token_cache : parent->disable_token_cache;
  
  merged->principal = child->principal != NULL ? child->principal : parent->principal;
  
  merged->keytab = child->keytab != NULL ? child->keytab : parent->keytab;
  
  merged->default_keytab = child->default_keytab != NULL ? child->default_keytab : parent->default_keytab;
  
  merged->default_principal = child->default_principal != NULL ? child->default_principal : parent->default_principal;
  
  merged->afs_cell = child->afs_cell != NULL ? child->afs_cell : parent->afs_cell;

  merged->afs_cell_realm = child->afs_cell_realm != NULL ? child->afs_cell_realm : parent->afs_cell_realm;
  
  return (void *) merged;
  
}

static void *waklog_merge_server_config(MK_POOL *p, void *parent_conf, void *newloc_conf) {

  waklog_config *merged = ( waklog_config * ) ap_pcalloc(p, sizeof(waklog_config ) );
  waklog_config *pconf = ( waklog_config * ) parent_conf;
  waklog_config *nconf = ( waklog_config * ) newloc_conf;
  
  merged->protect = nconf->protect == WAKLOG_UNSET ? pconf->protect : nconf->protect;

  merged->usertokens = nconf->usertokens == WAKLOG_UNSET ? pconf->usertokens : nconf->usertokens;

  merged->disable_token_cache = nconf->disable_token_cache == WAKLOG_UNSET ? pconf->disable_token_cache : nconf->disable_token_cache;

  merged->keytab = nconf->keytab == NULL ? ap_pstrdup(p, pconf->keytab) : 
    ( nconf->keytab == NULL ? NULL : ap_pstrdup(p, nconf->keytab) );
    
  merged->principal = nconf->principal == NULL ? ap_pstrdup(p, pconf->principal) : 
      ( nconf->principal == NULL ? NULL : ap_pstrdup(p, nconf->principal) );
      
  merged->afs_cell = nconf->afs_cell == NULL ? ap_pstrdup(p, pconf->afs_cell) : 
      ( nconf->afs_cell == NULL ? NULL : ap_pstrdup(p, nconf->afs_cell) );    
  
  merged->afs_cell_realm = nconf->afs_cell_realm  == NULL ? ap_pstrdup(p, pconf->afs_cell_realm) : 
      ( nconf->afs_cell_realm == NULL ? NULL : ap_pstrdup(p, nconf->afs_cell_realm) );    
  
  merged->default_keytab = nconf->default_keytab == NULL ? ap_pstrdup(p, pconf->default_keytab) : 
        ( nconf->default_keytab == NULL ? NULL : ap_pstrdup(p, nconf->default_keytab) );

  merged->default_principal = nconf->default_principal == NULL ? ap_pstrdup(p, pconf->default_principal) : 
        ( nconf->default_principal == NULL ? NULL : ap_pstrdup(p, nconf->default_principal) );
  
  
  return (void *) merged;
  
}
                                                                                          
static const char *
set_waklog_enabled (cmd_parms * params, void *mconfig, int flag)
{
  waklog_config *cfg = mconfig ? ( waklog_config * ) mconfig : 
    ( waklog_config * ) ap_get_module_config(params->server->module_config, &waklog_module );

  cfg->protect = flag;
  cfg->configured = 1;
  log_error (APLOG_MARK, APLOG_DEBUG, 0, params->server,
             "mod_waklog: waklog_enabled set on %s", cfg->path ? cfg->path : "NULL");
  return (NULL);
}


/* this adds a principal/keytab pair to get their tokens renewed by the
   child process every few centons. */

void add_to_renewtable(MK_POOL *p, char *keytab, char *principal) {

  int i;
  
  if ( renewcount >= SHARED_TABLE_SIZE ) {
    log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "mod_waklog: big problem.  Increase the SHARED_TABLE_SIZE or \
      decrease your tokens.");
    return;
  }
  
  /* check to see if it's already there */
  
  for ( i = 0; i < renewcount; i++ ) {
    if ( ! strcmp(renewtable[i].principal, principal ) ) {
      return;
    }
  }

  renewtable[renewcount].keytab = ap_pstrdup(p, keytab);
  renewtable[renewcount].principal = ap_pstrdup(p, principal);
  renewtable[renewcount].lastrenewed = 0;
  ++renewcount;

}

static const char *
set_waklog_location_principal (cmd_parms *params, void *mconfig, char *principal, char *keytab)
{
  waklog_config *cfg = mconfig ? ( waklog_config * ) mconfig : 
    ( waklog_config * ) ap_get_module_config(params->server->module_config, &waklog_module );

  log_error (APLOG_MARK, APLOG_DEBUG, 0, params->server,
             "mod_waklog: configuring principal: %s, keytab: %s", principal, keytab);
                
        cfg->principal = ap_pstrdup(params->pool, principal);
  cfg->keytab = ap_pstrdup (params->pool, keytab);
  
  add_to_renewtable(params->pool, keytab, principal);
  
  cfg->configured = 1;
  
  return (NULL);
}

static const char *
set_waklog_afs_cell (cmd_parms * params, void *mconfig, char *file)
{
  waklog_config *waklog_mconfig = ( waklog_config * ) mconfig;
  waklog_config *waklog_srvconfig =
    ( waklog_config * ) ap_get_module_config(params->server->module_config, &waklog_module );

  log_error (APLOG_MARK, APLOG_INFO, 0, params->server,
             "mod_waklog: will use afs_cell: %s", file);

  // Prefer afs/cell@REALM over afs@REALM, just like the OpenAFS tools
  waklog_srvconfig->cell_in_principal = 1;

  waklog_srvconfig->afs_cell = ap_pstrdup (params->pool, file);
  waklog_srvconfig->configured = 1;

  if (waklog_mconfig != NULL) {
    waklog_mconfig->cell_in_principal = waklog_srvconfig->cell_in_principal;
    waklog_mconfig->afs_cell = ap_pstrdup (params->pool, file);
    waklog_mconfig->configured = 1;
  }
  return (NULL);
}

static const char *
set_waklog_afs_cell_realm (cmd_parms * params, void *mconfig, char *file)
{
  waklog_config *waklog_mconfig = ( waklog_config * ) mconfig;
  waklog_config *waklog_srvconfig =
    ( waklog_config * ) ap_get_module_config(params->server->module_config, &waklog_module );

  log_error (APLOG_MARK, APLOG_INFO, 0, params->server,
             "mod_waklog: will use afs_cell_realm: %s", file);

  waklog_srvconfig->afs_cell_realm = ap_pstrdup (params->pool, file);

  if (waklog_mconfig != NULL) {
    waklog_mconfig->afs_cell_realm = ap_pstrdup (params->pool, file);
  }
  return (NULL);
}

static const char *
set_waklog_default_principal (cmd_parms * params, void *mconfig, char *principal, char *keytab)
{
  waklog_config *cfg = mconfig ? ( waklog_config * ) mconfig : 
    ( waklog_config * ) ap_get_module_config(params->server->module_config, &waklog_module );

  waklog_config *srvcfg = ( waklog_config * ) ap_get_module_config(params->server->module_config, &waklog_module );

  log_error (APLOG_MARK, APLOG_DEBUG, 0, params->server,
             "mod_waklog: set default princ/keytab: %s, %s for %s", principal, keytab, cfg->path ? cfg->path : "NULL");

  cfg->default_principal = ap_pstrdup (params->pool, principal);
  cfg->default_keytab = ap_pstrdup(params->pool, keytab );
  
  /* this also gets set at the server level */
  if ( mconfig && ( ! cfg->path ) ) {
    srvcfg->default_principal = ap_pstrdup (params->pool, principal);
    srvcfg->default_keytab = ap_pstrdup(params->pool, keytab );
  } else {
    log_error(APLOG_MARK, APLOG_ERR, 0, params->server, "only able to set default principal on a global level!");
    return "Unable to set DefaultPrincipal outside of top level config!";
  }
  
  add_to_renewtable( params->pool, keytab, principal );
 
  cfg->configured = 1;
  
  return (NULL);
}

static const char *
set_waklog_use_usertokens (cmd_parms * params, void *mconfig, int flag)
{
  waklog_config *cfg = mconfig ? ( waklog_config * ) mconfig : 
    ( waklog_config * ) ap_get_module_config(params->server->module_config, &waklog_module );

  cfg->usertokens = flag;

  cfg->configured = 1;

  log_error (APLOG_MARK, APLOG_DEBUG, 0, params->server,
             "mod_waklog: waklog_use_user_tokens set");
  return (NULL);
}


static const char *
set_waklog_disable_token_cache (cmd_parms * params, void *mconfig, int flag)
{
  waklog_config *cfg = mconfig ? ( waklog_config * ) mconfig : 
    ( waklog_config * ) ap_get_module_config(params->server->module_config, &waklog_module );

  cfg->disable_token_cache = flag;

  cfg->configured = 1;

  log_error (APLOG_MARK, APLOG_DEBUG, 0, params->server,
             "mod_waklog: waklog_disable_token_cache set");
  return (NULL);
}


#ifndef APACHE2
static void waklog_child_exit( server_rec *s, MK_POOL *p ) {
#else
apr_status_t waklog_child_exit( void *sr ) {

  server_rec *s = (server_rec *) sr;
#endif
  
  if ( child.ccache ) {
    krb5_cc_close(child.kcontext, child.ccache);
  }
  
  if ( child.kcontext ) {
    krb5_free_context(child.kcontext);
  }
  
  /* forget our tokens */
  
  ktc_ForgetAllTokens ();
  
  log_error (APLOG_MARK, APLOG_DEBUG, 0, s,
             "mod_waklog: waklog_child_exit complete");

#ifdef APACHE2
  return APR_SUCCESS;
#endif
  
}

static void
#ifdef APACHE2
waklog_child_init (MK_POOL * p, server_rec * s)
#else
waklog_child_init (server_rec * s, MK_POOL * p)
#endif
{

  krb5_error_code code;
  waklog_config *cfg;
  
  char *cell;
  
  log_error (APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: child_init called for pid %d", getpid());
  
  if ( !sharedspace ) {
    log_error( APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: child_init called without shared space? %d", getpid());
    return;
  }
  
  log_error (APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: child_init called for pid %d", getpid());

  memset (&child, 0, sizeof(child));
  
  if ( ( code = krb5_init_context(&child.kcontext) ) ) {
    log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: can't init kerberos context %d", code );
  }
  
  if ( ( code = krb5_cc_resolve(child.kcontext, "MEMORY:tmpcache", &child.ccache) ) ) {
    log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: can't initialize in-memory credentials cache %d", code );
  }
  
  if ( pag_for_children ) {
    k_setpag ();
  }

  getModConfig (cfg, s);

  if ( cfg->default_principal != NULL ) {
    log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: child_init setting default user %s, %s", cfg->default_principal, cfg->default_keytab);
    set_auth( s, NULL, 0, cfg->default_principal, cfg->default_keytab, 0);
  }

  cell = strdup(cfg->afs_cell);
  pr_Initialize(  0, AFSDIR_CLIENT_ETC_DIR, cell );

#ifdef APACHE2
  apr_pool_cleanup_register(p, s, waklog_child_exit, apr_pool_cleanup_null);
#endif

  log_error (APLOG_MARK, APLOG_DEBUG, 0, s,
             "mod_waklog: child_init returned");

  return;
}

command_rec waklog_cmds[] = {
  
  command ("WaklogAFSCell", set_waklog_afs_cell, 0, TAKE1,
           "Use the supplied AFS cell (required)"),

  command ("WaklogAFSCellRealm", set_waklog_afs_cell_realm, 0, TAKE1,
           "Assume that the AFS cell belongs to the specified Kerberos realm (optional)"),

  command ("WaklogEnabled", set_waklog_enabled, 0, FLAG,
           "enable waklog on a server, location, or directory basis"),

  command ("WaklogDefaultPrincipal", set_waklog_default_principal, 0, TAKE2,
           "Set the default principal that the server runs as"),

  command ("WaklogLocationPrincipal", set_waklog_location_principal, 0, TAKE2,
           "Set the principal on a <Location>-specific basis"),

  command ("WaklogDisableTokenCache", set_waklog_disable_token_cache, 0, FLAG,
           "Ignore the token cache (location-specific); useful for scripts that need kerberos tickets."),
  
  command ("WaklogUseUserTokens", set_waklog_use_usertokens, 0, FLAG,
           "Use the requesting user tokens (from webauth)"),
   
  {NULL}
};


/* not currently using this */

static int
token_cleanup (void *data)
{
  request_rec *r = (request_rec *) data;

  if (child.token.ticketLen)
    {
      memset (&child.token, 0, sizeof (struct ktc_token));

      ktc_ForgetAllTokens ();

      log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "mod_waklog: ktc_ForgetAllTokens succeeded: pid: %d",
                 getpid ());
    }
  return 0;
}

/* This function doesn't return anything but is passed to ap_bspawn_child on
 * Apache 1 which expects it to return a pid as an int. For want of better
 * understanding, err on the side of not changing Apache 1 code while fixing
 * the compile warning on Apache 2. */
#ifdef APACHE2
static void
#else
static int
#endif
waklog_child_routine (void *data, child_info * pinfo)
{
  int i;
  server_rec *s = (server_rec *) data;
  krb5_error_code code; 
  char *cell;
  time_t sleep_time = ( TKT_LIFE / 2 ) ;
  time_t when;
  time_t left;
  waklog_config *cfg;
  
  getModConfig( cfg, s );
  
  log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: waklog_child_routine started, running as %d", getuid());
  
  memset (&child, 0, sizeof(child));
  
  if ( ( code = krb5_init_context(&child.kcontext) ) ) {
    log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: can't init kerberos context %d", code );
  }
  
  if ( ( code = krb5_cc_resolve(child.kcontext, "MEMORY:tmpcache", &child.ccache) ) ) {
    log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: can't initialize in-memory credentials cache %d", code );
  }
  
  log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: about to pr_Initialize");

  /* need to do this so we can make PTS calls */
  cell = strdup(cfg->afs_cell); /* stupid */
  pr_Initialize(  0, AFSDIR_CLIENT_ETC_DIR, cell );
 
  log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: still here");

  while(1) {
  
    for ( i = 0; i < renewcount; ++i ) {
      renewtable[i].lastrenewed = time(0);
      log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: (pid %d) renewing %s / %s", getpid(), renewtable[i].principal, 
         renewtable[i].keytab);
      
      set_auth( s, NULL, 0, renewtable[i].principal, renewtable[i].keytab, 1 );
      
      /* if this is our default token, we want to "stash" it in our current PAG so the parent maintains readability of
         things that it needs to read */
      
      if ( cfg && cfg->default_principal && ( ! strcmp(cfg->default_principal, renewtable[i].principal ) ) ) {
        log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: renewing/setting default tokens" );
        set_auth( s, NULL, 0, renewtable[i].principal, renewtable[i].keytab, 0 );
      }
      
    }

    sharedspace->renewcount++;
    
    left = sleep_time;
    
    while( left > 5 ) {
      when = time(0);
      
      sleep(left);
      
      left -= ( time(0) - when );
    }
    
  }

  pr_End();

}

#ifdef APACHE2
static int
waklog_init_handler (apr_pool_t * p, apr_pool_t * plog,
                     apr_pool_t * ptemp, server_rec * s)
{
  int rv;
  extern char *version;
  apr_proc_t *proc;
  waklog_config *cfg;
  void *data;
  int fd = -1;
  int use_existing = 1;
  int oldrenewcount;
  char cache_file[MAXNAMELEN];
#ifdef use_pthreads
  pthread_rwlockattr_t rwlock_attr;
#endif


  getModConfig (cfg, s);

  /* initialize_module() will be called twice, and if it's a DSO
   * then all static data from the first call will be lost. Only
   * set up our static data on the second call. 
   * see http://issues.apache.org/bugzilla/show_bug.cgi?id=37519 */
  apr_pool_userdata_get (&data, userdata_key, s->process->pool);


  if (cfg->afs_cell==NULL) {
      log_error (APLOG_MARK, APLOG_ERR, 0, s,
                 "mod_waklog: afs_cell==NULL; please provide the WaklogAFSCell directive");
      /** clobber apache */
      exit(-1);
  }

  if (!data)
    {
      apr_pool_userdata_set ((const void *) 1, userdata_key,
                             apr_pool_cleanup_null, s->process->pool);
    }
  else
    {
      log_error (APLOG_MARK, APLOG_INFO, 0, s,
                 "mod_waklog: version %s initialized for cell %s", version, cfg->afs_cell);

      if ( sharedspace ) {
        log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: shared memory already allocated." );
      } else {

        snprintf( cache_file, MAXNAMELEN, "/tmp/waklog_cache.%d", getpid() );

        if ( ( fd = open( cache_file, O_RDWR, 0600 ) ) == -1 ) {

          if ( errno == ENOENT ) {
          
            log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: creating shared token cache file %s", cache_file );
            use_existing = 0;
            if ( ( fd = open( cache_file, O_RDWR|O_CREAT|O_TRUNC, 0600 ) ) == -1 ) {
              log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: cannot create shared token cache file %s (%d)", cache_file, errno );
              exit(errno);
            }
          } else {
            log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: cannot open existing shared token cache file %s (%d)", cache_file, errno );
          }
        }

        if ( use_existing == 0 ) {
          struct sharedspace_s bob;
          log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: sizing our cache file %d to %d", fd, sizeof(struct sharedspace_s) );
          memset( &bob, 0, sizeof(struct sharedspace_s));
          if ( write(fd, &bob, sizeof(struct sharedspace_s)) != sizeof(struct sharedspace_s) ) {
            log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: failed to write to our cache file %s (%d)", cache_file, errno );
            exit(errno);
          }
          log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: done sizing our cache file to %d", sizeof(struct sharedspace_s) );
        }

        /* mmap the region */

        if ( ( sharedspace = (struct sharedspace_s *) mmap ( NULL, sizeof(struct sharedspace_s), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0 ) ) != MAP_FAILED ) {
          int err = 0;
          log_error( APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: shared mmap region ok %d", sharedspace );
          err = unlink(cache_file);
          if (err) {
            log_error( APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: unable to delete %s due to %d", cache_file, errno);
          } else {
            log_error( APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: shared cache unlinked (will be deleted when Apache quits)");
          }
        } else {
           log_error( APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: mmap failed %d", errno );
           exit(errno);
        }
      }

#ifdef use_pthreads
#define locktype pthread_rwlock_t
#else
#define locktype rwlock_t
#endif

      if ( ( sharedlock = ( locktype * ) mmap ( NULL, sizeof(locktype), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANON, -1, 0 ) ) != NULL ) {
#ifndef use_pthreads
        rwlock_init(sharedlock, USYNC_PROCESS, NULL );
#else
        pthread_rwlockattr_init(&rwlock_attr);
        pthread_rwlockattr_setpshared(&rwlock_attr, PTHREAD_PROCESS_SHARED);
        pthread_rwlock_init(sharedlock, &rwlock_attr );
#endif
      } else {
        log_error( APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: rwlock mmap failed %d", errno );
      }

#undef locktype

      /* set our default tokens */

      oldrenewcount = sharedspace->renewcount;

      pag_for_children = 0;

      proc = (apr_proc_t *) ap_pcalloc (s->process->pool, sizeof (apr_proc_t));

      rv = apr_proc_fork (proc, s->process->pool);

      if (rv == APR_INCHILD)
        {
          waklog_child_routine (s, NULL);
        }
      else
        {
          apr_pool_note_subprocess (s->process->pool, proc, APR_KILL_ALWAYS);
        }
      /* parent and child */
      cfg->forked = proc->pid;
      pag_for_children = 1;

      if ( use_existing == 0 ) {
        /* wait here until our child process has gone and done it's renewing thing. */
        while( sharedspace->renewcount == oldrenewcount  ) {
          log_error( APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: waiting for tokens..." );
          sleep(2);
        }
      }

      if ( cfg->default_principal ) {
        set_auth( s, NULL, 0, cfg->default_principal, cfg->default_keytab, 0);
      }
    }
  return 0;
}
#else
static void
waklog_init (server_rec * s, MK_POOL * p)
{
  extern char *version;
  int pid;
  waklog_config *cfg;
  int fd = -1;
  int use_existing = 1;
  int oldrenewcount;
  char cache_file[MAXNAMELEN];
#ifdef use_pthreads
  pthread_rwlockattr_t rwlock_attr;
#endif

  log_error (APLOG_MARK, APLOG_DEBUG, 0, s,
             "mod_waklog: version %s initialized.", version);

  if ( sharedspace ) {
    log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: shared memory already allocated." );
  } else {
    
    snprintf( cache_file, MAXNAMELEN, "/tmp/waklog_cache.%d", getpid() );
    
    if ( ( fd = open( cache_file, O_RDWR, 0600 ) ) == -1 ) {
      
      if ( errno == ENOENT ) {

        log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: creating shared token cache file %s", cache_file );
        use_existing = 0;
        if ( ( fd = open( cache_file, O_RDWR|O_CREAT|O_TRUNC, 0600 ) ) == -1 ) {          
          log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: cannot create shared token cache file %s (%d)", cache_file, errno );
          exit(errno);
        } 
      } else {
        log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: cannot open existing shared token cache file %s (%d)", cache_file, errno );
      }
   
    }
    
    if ( use_existing == 0 ) {
      struct sharedspace_s bob;
      log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: sizing our cache file %d to %d", fd, sizeof(struct sharedspace_s) );
      memset( &bob, 0, sizeof(struct sharedspace_s));
      write(fd, &bob, sizeof(struct sharedspace_s));
      log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: done sizing our cache file to %d", sizeof(struct sharedspace_s) );
    }

    /* mmap the region */
    
    if ( ( sharedspace = (struct sharedspace_s *) mmap ( NULL, sizeof(struct sharedspace_s), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0 ) ) != (void *) -1 ) {
      log_error( APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: shared mmap region ok %d", sharedspace );
      close(fd);
    } else {
      log_error( APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: mmap failed %d", errno );
      exit(errno);
    }
  }

#ifdef use_pthreads
#define locktype pthread_rwlock_t
#else
#define locktype rwlock_t
#endif

  /* mmap our shared space for our lock */  
  if ( ( sharedlock = ( locktype * ) mmap ( NULL, sizeof(locktype), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANON, -1, 0 ) ) )  {
#ifndef use_pthreads
    rwlock_init(sharedlock, USYNC_PROCESS, NULL );
#else
    pthread_rwlockattr_init(&rwlock_attr);
    pthread_rwlockattr_setpshared(&rwlock_attr, PTHREAD_PROCESS_SHARED);
    pthread_rwlock_init(sharedlock, &rwlock_attr );
#endif
  } else {
    log_error( APLOG_MARK, APLOG_DEBUG, 0, s, "mod_waklog: rwlock mmap failed %d", errno );
  }

#undef locktype

  /* set our default tokens */
  
  getModConfig (cfg, s);
                
        oldrenewcount = sharedspace->renewcount;
                
        pag_for_children = 0;
                
        pid = ap_bspawn_child (p, waklog_child_routine, s, kill_always,
                         NULL, NULL, NULL);                     
        
        pag_for_children = 1;
        
  log_error (APLOG_MARK, APLOG_DEBUG, 0, s,
             "mod_waklog: ap_bspawn_child: %d.", pid);
  
  if ( use_existing == 0 ) {
    /* wait here until our child process has gone and done it's renewing thing. */
    while( sharedspace->renewcount == oldrenewcount  ) {
      log_error( APLOG_MARK, APLOG_ERR, 0, s, "mod_waklog: waiting for tokens..." );
      sleep(2);
    }
  }
  
  if ( cfg->default_principal ) {
    set_auth( s, NULL, 0, cfg->default_principal, cfg->default_keytab, 0);
  }

}
#endif

static int
waklog_phase0 (request_rec * r)
{
  waklog_config *cfg;

  log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server,
             "mod_waklog: phase0 called");

  cfg = retrieve_config(r);

  if ( get_cfg_protect(cfg) && cfg->principal ) {
    log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "mod_waklog: phase0 using user %s", cfg->principal);
    set_auth(r->server, r, 0, cfg->principal, cfg->keytab, 0);
  } else if ( cfg->default_principal ) {
    log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "mod_waklog: phase0 using default user %s", cfg->default_principal);
    set_auth(r->server, r, 0, cfg->default_principal, cfg->default_keytab, 0);
  } else {

    if (child.token.ticketLen) {
      memset( &child.token, 0, sizeof (struct ktc_token) );
      ktc_ForgetAllTokens();
    }

    log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "mod_waklog: phase0 not doing nothin.");
  }

  return DECLINED;
}

static int
waklog_phase1 (request_rec * r)
{
  waklog_config *cfg;

  log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server,
             "mod_waklog: phase1 called");

  cfg = retrieve_config(r);

  if ( get_cfg_protect(cfg) && cfg->principal ) {
    log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "mod_waklog: phase1 using user %s", cfg->principal);
    set_auth(r->server, r, 0, cfg->principal, cfg->keytab, 0);
  } else if ( cfg->default_principal ) {
    log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "mod_waklog: phase1 using default user %s", cfg->default_principal);
    set_auth(r->server, r, 0, cfg->default_principal, cfg->default_keytab, 0);
  } else {
    log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "mod_waklog: phase1 not doing nothin.");
  }

  return DECLINED;
}

static int
waklog_phase3 (request_rec * r)
{
  waklog_config *cfg;

  log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server,
             "mod_waklog: phase 3 called");

  cfg = retrieve_config(r);
  
  if ( get_cfg_protect(cfg) && cfg->principal ) {
    log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "mod_waklog: phase3 using user %s", cfg->principal);
    set_auth(r->server, r, 0, cfg->principal, cfg->keytab, 0);
  } else if ( cfg->default_principal ) {
    log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "mod_waklog: phase3 using default user %s", cfg->default_principal);
    set_auth(r->server, r, 0, cfg->default_principal, cfg->default_keytab, 0);
  } else {
    log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "mod_waklog: phase3 not doing nothin.");
  }

  return DECLINED;
}

static int
waklog_phase6 (request_rec * r)
{
  waklog_config *cfg;

  log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server,
             "mod_waklog: phase6 called");

  cfg = retrieve_config(r);
  
  if ( get_cfg_protect(cfg) && cfg->principal ) {
    log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "mod_waklog: phase6 using user %s", cfg->principal);
    set_auth(r->server, r, 0, cfg->principal, cfg->keytab, 0);
  } else if ( cfg->default_principal ) {
    log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "mod_waklog: phase6 using default user %s", cfg->default_principal);
    set_auth(r->server, r, 0, cfg->default_principal, cfg->default_keytab, 0);
  } else {
    log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "mod_waklog: phase6 not doing nothin.");
  }

  return DECLINED;
}

static int
waklog_phase7 (request_rec * r)
{
  waklog_config *cfg;
  int rc = 0;
  
  log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server,
             "mod_waklog: phase7 called");

  cfg = retrieve_config (r);

  if ( get_cfg_protect(cfg) && get_cfg_usertokens(cfg) ) {
    log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "mod_waklog: phase7 using usertokens");
    rc = set_auth( r->server, r, 1, NULL, NULL, 0);
  } else if ( get_cfg_protect(cfg) && cfg->principal ) {
    log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "mod_waklog: phase7 using user %s", cfg->principal);
    rc = set_auth( r->server, r, 0, cfg->principal, cfg->keytab, 0);
  } else if ( cfg->default_principal ) {
    log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "mod_waklog: phase7 using default user %s", cfg->default_principal);
    rc = set_auth( r->server, r, 0, cfg->default_principal, cfg->default_keytab, 0);
  } else {
    log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "mod_waklog: no tokens");
    if (child.token.ticketLen) {
       memset(&child.token, 0, sizeof(struct ktc_token));
       ktc_ForgetAllTokens();
    }
  }
  
  if ( rc ) {
    return 400;
  }
  
  return DECLINED;
}

static int
waklog_phase9 (request_rec * r)
{
  waklog_config *cfg;

  log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server,
             "mod_waklog: phase9 called");

  getModConfig (cfg, r->server);
  
  if ( cfg->default_principal ) {
    log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "mod_waklog: phase9 using default user %s", cfg->default_principal);
    set_auth( r->server, r, 0, cfg->default_principal, cfg->default_keytab, 0);
  }
  
  return DECLINED;
}


static
#ifdef APACHE2
  int
#else
  void
#endif
waklog_new_connection (conn_rec * c
#ifdef APACHE2
                       , void *dummy
#endif
  )
{
  
  waklog_config *cfg;
  
  log_error (APLOG_MARK, APLOG_DEBUG, 0, c->base_server,
             "mod_waklog: new_connection called: pid: %d", getpid ());
        
        getModConfig(cfg, c->base_server);
        
        if ( cfg->default_principal ) {
          log_error(APLOG_MARK, APLOG_DEBUG, 0, c->base_server, "mod_waklog: new conn setting default user %s",
          cfg->default_principal);
          set_auth( c->base_server, NULL, 0, cfg->default_principal, cfg->default_keytab, 0);
        }     
             
             
  return
#ifdef APACHE2
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

#ifndef APACHE2
module MODULE_VAR_EXPORT waklog_module = {
  STANDARD_MODULE_STUFF,
  waklog_init,                        /* module initializer                  */
  waklog_create_dir_config,           /* create per-dir    config structures */
  waklog_merge_dir_config,            /* merge  per-dir    config structures */
  waklog_create_server_config,        /* create per-server config structures */
  waklog_merge_dir_config,            /* merge  per-server config structures */
  waklog_cmds,                        /* table of config file commands       */
  NULL,                               /* [#8] MIME-typed-dispatched handlers */
  waklog_phase1,                      /* [#1] URI to filename translation    */
  NULL,                               /* [#4] validate user id from request  */
  NULL,                               /* [#5] check if the user is ok _here_ */
  waklog_phase3,                      /* [#3] check access by host address   */
  waklog_phase6,                      /* [#6] determine MIME type            */
  waklog_phase7,                      /* [#7] pre-run fixups                 */
  waklog_phase9,                      /* [#9] log a transaction              */
  waklog_phase2,                      /* [#2] header parser                  */
  waklog_child_init,                  /* child_init                          */
  waklog_child_exit,                  /* child_exit                          */
  waklog_phase0                       /* [#0] post read-request              */
#ifdef EAPI
    , NULL,                           /* EAPI: add_module                    */
  NULL,                               /* EAPI: remove_module                 */
  NULL,                               /* EAPI: rewrite_command               */
  waklog_new_connection               /* EAPI: new_connection                */
#endif
};
#else
static void
waklog_register_hooks (apr_pool_t * p)
{
    ap_hook_translate_name (waklog_phase1, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_header_parser (waklog_phase2, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_access_checker (waklog_phase3, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_type_checker (waklog_phase6, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_fixups (waklog_phase7, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_log_transaction (waklog_phase9, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_child_init (waklog_child_init, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_post_read_request (waklog_phase0, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_pre_connection (waklog_new_connection, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_post_config (waklog_init_handler, NULL, NULL, APR_HOOK_MIDDLE);
}


module AP_MODULE_DECLARE_DATA waklog_module = {
  STANDARD20_MODULE_STUFF,
  waklog_create_dir_config,     /* create per-dir    conf structures  */
  waklog_merge_dir_config,      /* merge  per-dir    conf structures  */
  waklog_create_server_config,  /* create per-server conf structures  */
  waklog_merge_dir_config,      /* merge  per-server conf structures  */
  waklog_cmds,                  /* table of configuration directives  */
  waklog_register_hooks         /* register hooks                     */
};
#endif
