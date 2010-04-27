/*
 *  $Id: clutch.c,v 1.3 2002/05/05 22:27:28 route Exp $
 *
 *  Building Open Source Network Security Tools
 *  clutch.c - libdnet example code
 *
 *  Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
 *                2002 Adam O'Donnell <adam@IO.ece.drexel.edu>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "./clutch.h"
#include <libnet.h>


int
main(int argc, char **argv)
{
    int c, n, sleep_int;
    char *filename;
    struct clutch_pack cp;

    printf("Clutch 1.0 [ARP cache / route table monitoring tool]\n");
    printf("<ctrl-c> to quit\n");

    sleep_int = 1;
    filename = NULL;
    while ((c = getopt(argc, argv, "c:ehs:v")) != EOF)
    {
        switch (c)
        {
            case 'c':
                filename = optarg;
                break;
            case 'e':
                cp.flags |= ENFORCE;
                break;
            case 'h':
                usage(argv[0]);
                exit(EXIT_FAILURE);
            case 'v':
                cp.flags |= VERBOSE;
                break;
            case 's':
                sleep_int = atoi(optarg);
                break;
            default:
                usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (filename == NULL)
    {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    if (cp.flags & VERBOSE)
    {
        printf("Verbose mode is on.\n");
    }
    if (cp.flags & ENFORCE)
    {
        printf("Strict policy enforcement in effect.\n");
    }

    /*
     *  Initialize the program.  Open all file handles and parse the
     *  configuration file.
     */
    n = clutch_init(&cp, filename);
    if (n == -1)
    {
        return (EXIT_FAILURE);
    }
    if (n == 0)
    {
        fprintf(stderr, "No rules to process!\n");
        return (EXIT_FAILURE);
    }

    fprintf(stderr, "State database loaded (%d rule(s)).\n", n);
    fprintf(stderr, "Program initialized, watching for violations...\n");

    for (; ; sleep(sleep_int))
    {
        /*
         *  Run through the ARP cache and routing table and check them
         *  against our rules to ensure no malcontents have tampered with
         *  them.
         *
         *  One thing to notice about this program is that we don't
         *  explicitly free memory anywhere.  This isn't considered a
         *  high priority however, since once we malloc memory for our
         *  state database, we need all of it until the program quits,
         *  in which case we rely on the operating system to reclaim
         *  our used resources.  Besides, we're done at that point, so
         *  who cares!
         */
        if (arp_loop(cp.a, check_arp_cache, &cp) == -1)
        {
            fprintf(stderr, "error checking ARP cache\n");
        }
        if (route_loop(cp.r, check_route_table, &cp) == -1)
        {
            fprintf(stderr, "error checking route table\n");
        }
    }
    exit(EXIT_SUCCESS);
}


int
clutch_init(struct clutch_pack *cp, char *filename)
{
    int n;
    FILE *fp;

    /* open the config file passed in the by user at the CLI */
    fp = fopen(filename, "r+");
    if (fp == NULL)
    {
        perror("clutch_init(): fopen()");
        return (-1);
    }

    /* get an ARP cache handle */
    cp->a = arp_open();
    if (cp->a == NULL)
    {
        perror("clutch_init(): arp_open()");
        goto bad;
    }
    /* get a route table handle */
    cp->r = route_open();
    if (cp->r == NULL)
    {
        perror("clutch_init(): route_open()");
        goto bad;
    }

    /*
     *  Parse the configuration file and build the state table for
     *  Clutch.
     */
    n = parse_config(cp, fp);
    if (n == -1)
    {
        fprintf(stderr, "parse_config fatal error\n");
        goto bad;
    }
    else
    {
        return (n);
    }
bad:
    arp_close(cp->a);
    route_close(cp->r);
    return (-1);
}


int
parse_config(struct clutch_pack *cp, FILE *fp)
{
    int l, m;
    char buf[BUFSIZ];
    char *mac_p, *ip_p, *gw_p, *end_p;
    struct addr ip;
    struct addr gw;
    struct addr mac;

    /*
     *  Parse the config file with the following logic:
     *
     *  - Ignore all lines beginning with "#" or a whitespace character
     *  - If a line starts with ARP, parse it as an ARP mapping:
     *      - Expect "x:x:x:x:x:x -> y.y.y.y"
     *      - Non-fatal continue error if there's a lexical problem
     *      - Otherwise store it in the ARP cache mapping list
     *  - If a line starts with INT, parse it as an interface entry:
     *      - Expect "device flags"
     *      - Non-fatal continue error if there's a lexical problem
     *      - Otherwise store it in the interface list
     *  - If a line starts with RTE, parse it as a route entry:
     *      - Expect "x.x.x.x -> y.y.y.y"
     *      - Non-fatal continue error if there's a lexical problem
     *      - Otherwise store it in the route table list
     *  - Everything else is a non-fatal error
     */
    l = 0;
    m = 0;
    while (fgets(buf, sizeof (buf) - 1, fp))
    {
        /* count configuration file lines */
        l++;
        if (isspace(buf[0]) || buf[0] == '#')
        {
            /* blank link or comment */
            continue;
        }
        if (strstr(buf, "ARP"))
        {
            mac_p = buf;
            ip_p = strstr(buf, "->");
            if (ip_p == NULL)
            {
                goto error;
            }
            /* step past "ARP" */
            mac_p += 3;
            /* step past "->" */
            ip_p += 2;

            /* remove whitespace */
            STEPOVER_WS(mac_p);
            end_p = mac_p;

            /* get to the end of the MAC */
            while (isgraph(*end_p) && !(*end_p == '-'))
            {
                end_p++;
            }
            *end_p = NULL;

            if (addr_aton(mac_p, &mac) == -1)
            {
                goto error;
            }

            /* remove whitespace */
            STEPOVER_WS(ip_p);
            end_p = ip_p;

            /* get to the end of IP */
            STEPOVER_NONWS(end_p);
            *end_p = NULL;

            if (addr_aton(ip_p, &ip) == -1)
            {
                goto error;
            }

            /* scrape together some memory for the ARP entry here */
            if (new_list_entry(&cp, ARP, &mac, &ip) == -1)
            {
                perror("malloc");
                return (-1);
            }
            m++;
            if ((cp->flags) & VERBOSE)
            {
                printf("added ARP mapping rule %s -> %s\n",
                        addr_ntoa(&mac),
                        addr_ntoa(&ip));
            }
        }
        else if (strstr(buf, "RTE"))
        {
            ip_p = buf;
            gw_p = strstr(buf, "->"); // find next part of the data
            gw_p += 2;
            ip_p += 3;
      
            /* remove whitespace */
            STEPOVER_WS(ip_p);
            end_p = ip_p;

            /* get to the end of IP */
            while (isgraph(*end_p) && !(*end_p == '-'))
            {
                end_p++;
            }
            *end_p = NULL;

            if (addr_aton(ip_p, &ip) == -1)
            {
                goto error;
            }

            /* remove whitespace */
            STEPOVER_WS(gw_p);
            end_p = gw_p;

            STEPOVER_NONWS(end_p);
            *end_p = NULL;

            if (addr_aton(gw_p, &gw) == -1)
            {
                goto error;
            }

            /* scrape together some memory for the route entry here */
            if (new_list_entry(&cp, ROUTE, &ip, &gw) == -1)
            {
                perror("malloc");
                return (-1);
            }
            m++;
            if ((cp->flags) & VERBOSE)
            {
                printf("added route table rule %s -> %s\n",
                        addr_ntoa(&ip),
                        addr_ntoa(&gw));
            }
        }
        else
        {
error:
            fprintf(stderr,
                "unknown or malformed rule at line %03d\n", l);
        }
    }
    return (m);
}


int
new_list_entry(struct clutch_pack **cp, int type, struct addr *a1,
        struct addr *a2)
{
    switch (type)
    {
        case ARP:
        {
            struct clutch_arp_entry *p;
            if ((*cp)->cae == NULL)
            {
                /* create the head node on the list */
                (*cp)->cae = malloc(sizeof (struct clutch_arp_entry));
                if ((*cp)->cae == NULL)
                {
                    return (-1);
                }
                memset((*cp)->cae, 0, sizeof (struct clutch_arp_entry));
                memcpy(&(*cp)->cae->mac, a1, sizeof (struct addr));
                memcpy(&(*cp)->cae->ip, a2, sizeof (struct addr));
                (*cp)->cae->next = NULL;
                return (1);
            }
            else
            {
                /* walk to the end of the list */
                for (p = (*cp)->cae; p->next; p = p->next) ;

                p->next = malloc(sizeof (struct clutch_arp_entry));
                if (p->next == NULL)
                {
                    return (-1);
                }
                memset(p->next, 0, sizeof (struct clutch_arp_entry));
                p = p->next;
                memcpy(&p->mac, a1, sizeof (struct addr));
                memcpy(&p->ip, a2, sizeof (struct addr));
                p->next = NULL;
                return (1);
            }
        }
        case ROUTE:
        {
            struct clutch_route_entry *p;
            if ((*cp)->cre == NULL)
            {
                /* create the head node on the list */
                (*cp)->cre = malloc(sizeof (struct clutch_route_entry));
                if ((*cp)->cre == NULL)
                {
                    return (-1);
                }
                memset((*cp)->cre, 0, sizeof (struct clutch_route_entry));
                memcpy(&(*cp)->cre->ip, a1, sizeof (struct addr));
                memcpy(&(*cp)->cre->gw, a2, sizeof (struct addr));
                (*cp)->cre->next = NULL;
                return (1);
            }
            else
            {
                /* walk to the end of the list */
                for (p = (*cp)->cre; p->next; p = p->next) ;

                p->next = malloc(sizeof (struct clutch_route_entry));
                if (p->next == NULL)
                {
                    return (-1);
                }
                memset(p->next, 0, sizeof (struct clutch_route_entry));
                p = p->next;
                memcpy(&p->ip, a1, sizeof (struct addr));
                memcpy(&p->gw, a2, sizeof (struct addr));
                p->next = NULL;
            }
            return (1);
        }
        default:
        {
            return (-1);
        }
    }
    return (-1);
}


int
check_arp_cache(const struct arp_entry *ae, void *cp)
{
    struct clutch_pack *p;
    struct clutch_arp_entry *cae;
    const struct addr *pa;
    const struct addr *ha;

    p = (struct clutch_pack *)cp;
    pa = &ae->arp_pa;
    ha = &ae->arp_ha;

    /* run through the ARP cache rules */
    for (cae = (struct clutch_arp_entry *)p->cae; cae; cae = cae->next)
    {
        /* look for a hardware address match in the ARP cache */
        if (addr_cmp(ha, &cae->mac) == 0)
        {
            /* does it match our rule? */
            if (addr_cmp(pa, &cae->ip) != 0)
            {
                printf("[%s ARP cache rule violation: %s -> %s]\n",
                    get_time(), addr_ntoa(ha), addr_ntoa(pa));
                if ((p->flags) & VERBOSE)
                {
                    printf("[entry should be: %s -> %s]\n",
                        addr_ntoa(&cae->mac), addr_ntoa(&cae->ip));
                }
                if ((p->flags) & ENFORCE)
                {
                    /* reset the entry back to what it should be */
                    if (arp_delete(p->a, ae) == -1)
                    {
                        fprintf(stderr, "[can't reset ARP entry]\n");
                    }
                    else
                    {
                        /* setup new ARP entry */
                        struct arp_entry new_ae;
                        memcpy (&new_ae.arp_pa, &cae->ip,
                                sizeof (struct addr));
                        memcpy (&new_ae.arp_ha, &cae->mac,
                                sizeof (struct addr));

                        printf("[bogus ARP cache entry deleted]\n");
                        if (arp_add(p->a, &new_ae) == -1)
                        {
                            fprintf(stderr, "[can't reset ARP entry]\n");
                        }
                        else
                        {
                            printf("[correct ARP cache entry restored]\n");
                        }
                    }
                }
            }
        }
    }
    return (0);
}


int
check_route_table(const struct route_entry *re, void *cp)
{
    struct clutch_pack *p;
    struct clutch_route_entry *cre;
    const struct addr *dst;
    const struct addr *gw;

    p = (struct clutch_pack *)cp;
    dst = &re->route_dst;
    gw = &re->route_gw;

    /* run through the route table rules */
    for (cre = (struct clutch_route_entry *)p->cre; cre; cre = cre->next)
    {
        /* look for a destination IP match in the route table */
        if (addr_cmp(dst, &cre->ip) == 0)
        {
            /* does it match our rule? */
            if (addr_cmp(gw, &cre->gw) != 0)
            {
                printf("[%s route table rule violation: %s -> %s]\n",
                    get_time(), addr_ntoa(dst), addr_ntoa(gw));
                if ((p->flags) & VERBOSE)
                {
                    printf("[entry should be: %s -> %s]\n",
                        addr_ntoa(&cre->ip), addr_ntoa(&cre->gw));
                }
                if ((p->flags) & ENFORCE)
                {
                    /* reset the entry back to what it should be */
                    if (route_delete(p->r, re) == -1)
                    {
                        fprintf(stderr, "[can't reset route entry]\n");
                    }
                    else
                    {
                        /* setup new route entry */
                        struct route_entry new_re;
                        memcpy (&new_re.route_dst, &cre->ip,
                                sizeof (struct addr));
                        memcpy (&new_re.route_gw, &cre->gw,
                                sizeof (struct addr));

                        printf("[bogus route table entry deleted]\n");
                        if (route_add(p->r, &new_re) == -1) 
                        {
                            fprintf(stderr, "[can't reset route entry]\n");
                        }
                        else
                        {   
                            printf(
                                "[correct route table entry restored]\n");
                        }
                    }
                }
            }
        }
    }
    return (0);
}


char *
get_time()
{
    int i;
    time_t t;
    static char buf[26];
        
    t = time((time_t *)NULL);
    strcpy(buf, ctime(&t));
    
    /* cut out the day, year and \n */
    for (i = 0; i < 20; i++)
    {
        buf[i] = buf[i + 4];
    }
    buf[15] = 0;
            
    return (buf);
}


void
usage(char *name)
{
    fprintf(stderr, "usage: %s [options] -c config_file:\n"
                    "-c filename\tconfiguration file\n"
                    "-e\t\tenforce rules rather than just warn\n"
                    "-h\t\tthis jonk here\n"
                    "-s\t\tsleep interval in seconds\n"
                    "-v\t\tbe more verbose\n", name);

}


/* EOF */
