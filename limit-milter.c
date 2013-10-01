#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <time.h>
#include "libmilter/mfapi.h"
#include "libmilter/mfdef.h"
#include "khash.h"
#include "pthread.h"

#ifndef bool
# define bool   int
# define TRUE   1
# define FALSE  0
#endif /* ! bool */

#define EXPIRE_TIMER 60
#define COUNTER_LIMIT 3

typedef struct smtpinfo
{
    char *envelope_from;
    char *envelope_to;
    char *ident_from_to;
    int counter;
    int receive_time;
} smtpinfo_t;

typedef struct dbinfo
{
    char *ident_from_to;
    int counter;
    int receive_time;
} dbinfo_t;

#define SMTPINFO ((smtpinfo_t *) smfi_getpriv(ctx))

static pthread_mutex_t table_mutex = PTHREAD_MUTEX_INITIALIZER;

KHASH_MAP_INIT_STR(mailinfo, dbinfo_t*)
khash_t(mailinfo) *h;

void mailinfo_init()
{   
    h = kh_init(mailinfo);
}

static void mailinfo_add_ent(char *putent, int receive_time)
{
    khiter_t k;
    int ret;
    char *tmp= strdup(putent);

    pthread_mutex_lock(&table_mutex);
    k = kh_put(mailinfo, h, tmp, &ret);
    printf ("buckets = %d\n", kh_size(h));
    //printf ("tmp = %p\n", tmp);
    printf ("k = %d\n", k);
    //printf ("ret = %d\n", ret);
    //printf ("putent = %p\n", putent);
    //printf ("receive_time = %d\n", receive_time);
    if (kh_exist(h, k))
    {
        dbinfo_t *put;
        if (ret)
        {
            put = malloc(sizeof(dbinfo_t));
            put->counter = 0;
            put->receive_time = receive_time;
        }
        else
        {
            put = kh_value(h, k);
            put->counter++;
            put->receive_time = receive_time;
        }
        kh_value(h, k) = put;
        printf ("put->counter = %d\n", put->counter);
        //printf ("put->receive_time = %d\n", put->receive_time);
        //printf ("--------\n");
    }
    pthread_mutex_unlock(&table_mutex);
}

static int mailinfo_get_ent(char *getent)
{
    khiter_t k;
    int missing;
    dbinfo_t *get;

    pthread_mutex_lock(&table_mutex);
    k = kh_get(mailinfo, h, getent);
    missing = (k == kh_end(h));
    //printf ("tmp = %p\n", tmp);
    //printf ("k = %d\n", k);
    //printf ("getent = %p\n", getent);
    //printf ("missing = %d\n", missing);
    
    if (!missing)
    {
        get = kh_value(h, k);
        if (get == NULL)
        {
            pthread_mutex_unlock(&table_mutex);
            return SMFIS_CONTINUE;
        }
        pthread_mutex_unlock(&table_mutex);

        if (get->counter >= COUNTER_LIMIT)
        {
            printf ("get->counter = %d\n", get->counter);
            return SMFIS_TEMPFAIL;
        }
        else
        {
            return SMFIS_CONTINUE;
        }
    }
    pthread_mutex_unlock(&table_mutex);
    return SMFIS_CONTINUE;
}

static void mailinfo_del_ent(char *delent, int receive_time)
{
    khiter_t k;
    int missing;
    dbinfo_t *del;

    pthread_mutex_lock(&table_mutex);
    k = kh_get(mailinfo, h, delent);
    missing = (k == kh_end(h));

    if (missing) {
        del = kh_value(h, k);
        if (del != NULL) {
            free(del);
        }
        if (del->receive_time < receive_time - EXPIRE_TIMER)
        {
            if (kh_key(h, k) != NULL)
                free((void *)kh_key(h, k));
            kh_del(mailinfo, h, k);
        }
    }
    pthread_mutex_unlock(&table_mutex);
}



extern sfsistat xxfi_cleanup(SMFICTX *, bool);

/* connection info filter */
sfsistat
xxfi_connect(ctx, hostname, hostaddr)
    SMFICTX *ctx;
    char *hostname;
    _SOCK_ADDR *hostaddr;
{
    smtpinfo_t *info;
    info = (smtpinfo_t *)malloc(sizeof(smtpinfo_t));
    if (info == NULL)
    {
        return SMFIS_TEMPFAIL;
    }
    memset(info, '\0', sizeof *info);
    smfi_setpriv(ctx, info);
    return SMFIS_CONTINUE;
}

/* SMTP HELO command filter */
sfsistat
xxfi_helo(ctx, helohost)
    SMFICTX *ctx;
    char *helohost;
{
    return SMFIS_CONTINUE;
}

/* envelope sender filter */
sfsistat
xxfi_envfrom(ctx, argv)
    SMFICTX *ctx;
    char **argv;
{
    smtpinfo_t *info = SMTPINFO;
    int len;
    char *mailaddr = smfi_getsymval(ctx, "{mail_addr}");
    char *mail_from;
    //printf ("mailaddr = %s\n", mailaddr);
    //printf ("info->envelope_fromp = %p\n", info->envelope_from);
    len = strlen(mailaddr) + 1; 
    //printf ("len = %d\n", len);
    if ((mail_from = (char *)malloc(len)) == NULL)
    {
        return SMFIS_TEMPFAIL;
    }
    snprintf(mail_from, len, "%s", mailaddr);
    if (info->envelope_from != NULL)
    {
        free(info->envelope_from);
    }
    info->envelope_from = mail_from;
    //printf ("info->envelope_fromp = %p\n", info->envelope_from);
    //info->envelope_from = strdup(*argv);
    printf ("envelope_from = %s\n", info->envelope_from);
    return SMFIS_CONTINUE;
}

/* envelope recipient filter */
sfsistat
xxfi_envrcpt(ctx, argv)
    SMFICTX *ctx;
    char **argv;
{
    smtpinfo_t *info = SMTPINFO;
    int len,retval;
    char *rcptaddr = smfi_getsymval(ctx, "{rcpt_addr}");
    char *rcpt_to;
    char *ident_from_to;
    //snprintf(rcpt_to, sizeof rcpt_to, "%s", rcptaddr);
    //printf ("rcptaddr = %s\n", rcptaddr);
    len = strlen(rcptaddr) + 1;    
    if ((rcpt_to = (char *)malloc(len)) == NULL)
    {  
        return SMFIS_TEMPFAIL;
    }
    snprintf(rcpt_to, len, "%s", rcptaddr);
    if (info->envelope_to != NULL)
        free(info->envelope_to);
    info->envelope_to = rcpt_to;
    printf ("envelope_to = %s\n", info->envelope_to);
    len = strlen(info->envelope_from) + strlen(info->envelope_to) + 3;
    if ((ident_from_to = (char *)malloc(len)) == NULL)
    {  
        return SMFIS_TEMPFAIL;
    }
    if (info->ident_from_to != NULL)
        free(info->ident_from_to);
    sprintf(ident_from_to, "%s%s", info->envelope_from, info->envelope_to);
    info->ident_from_to = ident_from_to;
    printf ("ident_from_to = %s\n", info->ident_from_to);
    retval = mailinfo_get_ent(info->ident_from_to);
    return retval;
}

/* header filter */
sfsistat
xxfi_header(ctx, headerf, headerv)
    SMFICTX *ctx;
    char *headerf;
    unsigned char *headerv;
{
    return SMFIS_CONTINUE;
}

/* end of header */
sfsistat
xxfi_eoh(ctx)
    SMFICTX *ctx;
{
    return SMFIS_CONTINUE;
}

/* body block filter */
sfsistat
xxfi_body(ctx, bodyp, bodylen)
    SMFICTX *ctx;
    unsigned char *bodyp;
    size_t bodylen;
{
    return SMFIS_CONTINUE;
}

/* end of message */
sfsistat
xxfi_eom(ctx)
    SMFICTX *ctx;
{
    smtpinfo_t *info = SMTPINFO;
    time_t accept_time;
    bool ok = TRUE;
    time(&accept_time);
    info->receive_time = accept_time;
    //printf ("receive_time = %d\n", info->receive_time);
    //mailinfo_del_ent(info->ident_from_to, info->receive_time);
    mailinfo_add_ent(info->ident_from_to, info->receive_time);
    return SMFIS_CONTINUE;
}

/* message aborted */
sfsistat
xxfi_abort(ctx)
    SMFICTX *ctx;
{
    return xxfi_cleanup(ctx, FALSE);
}

/* session cleanup */
sfsistat
xxfi_cleanup(ctx, ok)
    SMFICTX *ctx;
    bool ok;
{
    return SMFIS_CONTINUE;
}

/* connection cleanup */
sfsistat
xxfi_close(ctx)
    SMFICTX *ctx;
{
    smtpinfo_t *info = SMTPINFO;
    if (info == NULL)
        return SMFIS_CONTINUE;
    if (info->envelope_from != NULL)
    {
        free(info->envelope_from);
        info->envelope_from = NULL;
    }
    if (info->envelope_to != NULL)
    {
        free(info->envelope_to);
        info->envelope_to = NULL;
    }
    if (info->ident_from_to != NULL)
    {
        free(info->ident_from_to);
        info->ident_from_to = NULL;
    }
    if (info->counter != 0)
        info->counter = 0;
    if (info->receive_time != 0)
        info->receive_time = 0;
    free(info);
    smfi_setpriv(ctx, NULL);
    return SMFIS_CONTINUE;
}

/* Once, at the start of each SMTP connection */
sfsistat
xxfi_unknown(ctx, cmd)
    SMFICTX *ctx;
    char *cmd;
{
    smtpinfo_t *info;
    return SMFIS_CONTINUE;
}

/* DATA command */
sfsistat
xxfi_data(ctx)
    SMFICTX *ctx;
{
    smtpinfo_t *info;
    return SMFIS_CONTINUE;
}

/* Once, at the start of each SMTP connection */
sfsistat
xxfi_negotiate(ctx, f0, f1, f2, f3, pf0, pf1, pf2, pf3)
    SMFICTX *ctx;
    unsigned long f0;
    unsigned long f1;
    unsigned long f2;
    unsigned long f3;
    unsigned long *pf0;
    unsigned long *pf1;
    unsigned long *pf2;
    unsigned long *pf3;
{
    smtpinfo_t *info;
    return SMFIS_ALL_OPTS;
}

struct smfiDesc smfilter =
{
    "MyMilter",                     /* filter name */
    SMFI_VERSION,                   /* version code */
    SMFIF_ADDHDRS|SMFIF_ADDRCPT,    /* flags */
    xxfi_connect,                   /* connection info filter */
    xxfi_helo,                      /* SMTP HELO command filter */
    xxfi_envfrom,                   /* envelope sender filter */
    xxfi_envrcpt,                   /* envelope recipient filter */
    xxfi_header,                    /* header filter */
    xxfi_eoh,                       /* end of header */
    xxfi_body,                      /* body block filter */
    xxfi_eom,                       /* end of message */
    xxfi_abort,                     /* message aborted */
    xxfi_close,                     /* connection cleanup */
    xxfi_unknown,                   /* unknown SMTP commands */
    xxfi_data,                      /* DATA command */
    xxfi_negotiate                  /* Once, at the start of each SMTP connection */
};

static void
usage(prog)
    char *prog;
{
    fprintf(stderr, "Usage: %s -p socket-addr [-t timeout]\n", prog);
}

int
main(argc, argv)
    int argc;
    char **argv;
{
    bool setconn = FALSE;
    int c;
    const char *args = "p:t:h";
    extern char *optarg;
    /* Process command line options */
    while ((c = getopt(argc, argv, args)) != -1)
    {
        switch (c)
        {
            case 'p':
                if (optarg == NULL || *optarg == '\0')
                {
                    (void) fprintf(stderr, "Illegal conn: %s\n", optarg);
                    exit(EX_USAGE);
                }
                if (smfi_setconn(optarg) == MI_FAILURE)
                {
                    (void) fprintf(stderr, "smfi_setconn failed\n");
                    exit(EX_SOFTWARE);
                }
/*
 * **  If we're using a local socket, make sure it
 * **  doesn't already exist.  Don't ever run this
 * **  code as root!!
 */
                if (strncasecmp(optarg, "unix:", 5) == 0)
                    unlink(optarg + 5);
                else if (strncasecmp(optarg, "local:", 6) == 0)
                    unlink(optarg + 6);
                setconn = TRUE;
                    break;
            case 't':
                if (optarg == NULL || *optarg == '\0')
                {
                    (void) fprintf(stderr, "Illegal timeout: %s\n", optarg);
                        exit(EX_USAGE);
                    }
                    if (smfi_settimeout(atoi(optarg)) == MI_FAILURE)
                    {
                        (void) fprintf(stderr, "smfi_settimeout failed\n");
                        exit(EX_SOFTWARE);
                    }
                    break;
            case 'h':
                default:
                usage(argv[0]);
                exit(EX_USAGE);
        }
    }
    if (!setconn)
    {
        fprintf(stderr, "%s: Missing required -p argument\n", argv[0]);
        usage(argv[0]);
        exit(EX_USAGE);
    }
    if (smfi_register(smfilter) == MI_FAILURE)
    {
        fprintf(stderr, "smfi_register failed\n");
        exit(EX_UNAVAILABLE);
    }
    mailinfo_init();
    return smfi_main();
}
/* eof */
