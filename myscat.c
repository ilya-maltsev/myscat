#ifndef lint
static char copyright[] =
"@(#) Copyright (c) 2014\n\
	Ilya Maltsev.e-mail:i.y.maltsev@yandex.ru.  All rights reserved.\n";
#endif /* not lint */



#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcre.h>
#include <time.h>
#include <string.h>


extern char *__progname;

int bflag, eflag, nflag, sflag, tflag, vflag;
int rval;
char *filename;

void cook_args(char *argv[]);
void cook_buf(FILE *);
void raw_args(char *argv[]);
void raw_cat(int);

int
main(int argc, char *argv[])
{
	int ch;
	setlocale(LC_ALL, "");

	while ((ch = getopt(argc, argv, "benstuv")) != -1)
		switch (ch) {
		case 'b':
			bflag = nflag = 1;	/* -b implies -n */
			break;
		case 'e':
			eflag = vflag = 1;	/* -e implies -v */
			break;
		case 'n':
			nflag = 1;
			break;
		case 's':
			sflag = 1;
			break;
		case 't':
			tflag = vflag = 1;	/* -t implies -v */
			break;
		case 'u':
			setbuf(stdout, NULL);
			break;
		case 'v':
			//vflag = 1;
			//break;
			(void)fprintf(stderr,
			    "Mysql general-log parser by Ilya Maltsev.e-mail:i.y.maltsev@yandex.ru.\n");
			exit(1);
		default:
			(void)fprintf(stderr,
			    "usage: %s [file ...]\n", __progname);
			exit(1);
			/* NOTREACHED */
		}
	argv += optind;

	if (bflag || eflag || nflag || sflag || tflag || vflag){
		cook_args(argv);
	}
	else{
		raw_args(argv);
	}
	if (fclose(stdout))
		err(1, "stdout");
	exit(rval);
	/* NOTREACHED */
}

void
cook_args(char **argv)
{
	FILE *fp;

	fp = stdin;
	filename = "stdin";
	do {
		if (*argv) {
			if (!strcmp(*argv, "-"))
				fp = stdin;
			else if ((fp = fopen(*argv, "r")) == NULL) {
				warn("%s", *argv);
				rval = 1;
				++argv;
				continue;
			}
			filename = *argv++;
		}
		cook_buf(fp);
		if (fp != stdin)
			(void)fclose(fp);
	} while (*argv);
}

void
cook_buf(FILE *fp)
{
	int ch, gobble, line, prev;

	line = gobble = 0;
	for (prev = '\n'; (ch = getc(fp)) != EOF; prev = ch) {
		if (prev == '\n') {
			if (sflag) {
				if (ch == '\n') {
					if (gobble)
						continue;
					gobble = 1;
				} else
					gobble = 0;
			}
			if (nflag && (!bflag || ch != '\n')) {
				(void)fprintf(stdout, "%6d\t", ++line);
				if (ferror(stdout))
					break;
			}
		}
		if (ch == '\n') {
			if (eflag && putchar('$') == EOF)
				break;
		} else if (ch == '\t') {
			if (tflag) {
				if (putchar('^') == EOF || putchar('I') == EOF)
					break;
				continue;
			}
		} else if (vflag) {
			if (!isascii(ch)) {
				if (putchar('M') == EOF || putchar('-') == EOF)
					break;
				ch = toascii(ch);
			}
			if (iscntrl(ch)) {
				if (putchar('^') == EOF ||
				    putchar(ch == '\177' ? '?' :
				    ch | 0100) == EOF)
					break;
				continue;
			}
		}
		if (putchar(ch) == EOF)
			break;
	}
	if (ferror(fp)) {
		warn("%s", filename);
		rval = 1;
		clearerr(fp);
	}
	if (ferror(stdout))
		err(1, "stdout");
}

void
raw_args(char **argv)
{
	int fd;
	fd = fileno(stdin);
	filename = "stdin";
	do {
		if (*argv) {
			if (!strcmp(*argv, "-"))
				fd = fileno(stdin);
			else if ((fd = open(*argv, O_RDONLY, 0)) < 0) {
				warn("%s", *argv);
				rval = 1;
				++argv;
				continue;
			}
			filename = *argv++;
		}

		raw_cat(fd);
		if (fd != fileno(stdin))
			(void)close(fd);
	} while (*argv);
}

void
raw_cat(int rfd)
{
    int wfd;
    ssize_t nr, nw, off,tnw,nnw;
    static size_t bsize;
    static char *buf = NULL;
    struct stat sbuf;

	pcre *re_mess, *re_pre_authf, *re_authf, *re_con, *re_que, *re_quit, *re_excp, *re_time;
	int rc_mess, rc_authf, rc_pre_authf, rc_con, rc_que, rc_quit, rc_excp, rc_time;
	const char *error_re;
	int   erroffset_re;

	re_mess = pcre_compile("\\s([0-9]*|\\-[0-9]*)\\s(Connect|Init|Query|Execute|Quit)\\s",PCRE_DOTALL,&error_re,&erroffset_re,0);
	if (!re_mess){
		fprintf(stdout,"Could not compile regex <Message> (offset: %d), %s\n", erroffset_re, error_re);
		exit(1);
	}

	re_pre_authf = pcre_compile("[a-zA-Z]+\\sAccess\\sdenied\\sfor\\suser\\s",PCRE_DOTALL,&error_re,&erroffset_re,0);
	if (!re_pre_authf){
		fprintf(stdout,"Could not compile regex <Pre Auth fail> (offset: %d), %s\n", erroffset_re, error_re);
		exit(1);
	}

	re_authf = pcre_compile("([0-9]*|\\-[0-9]*)\\s(Connect)\\s([^+^\n]*)()",PCRE_DOTALL,&error_re,&erroffset_re,0);
	if (!re_authf){
		fprintf(stdout,"Could not compile regex <Auth fail> (offset: %d), %s\n", erroffset_re, error_re);
		exit(1);
	}

	re_con = pcre_compile("([0-9]*|\\-[0-9]*)\\s(Connect)\\s([a-zA-Z0-9\\_\\-\\.\\@]*)\\s",PCRE_DOTALL,&error_re,&erroffset_re,0);
	if (!re_con){
		fprintf(stdout,"Could not compile regex <Connect> (offset: %d), %s\n", erroffset_re, error_re);
		exit(1);
	}

	re_que = pcre_compile("([0-9]*|\\-[0-9]*)\\s(Query|Execute|Init\\sDB)\\s(.*[^\n]*)",PCRE_DOTALL,&error_re,&erroffset_re,0);
	if (!re_que){
		fprintf(stdout,"Could not compile regex <Query> (offset: %d), %s\n", erroffset_re, error_re);
		exit(1);
	}

	re_quit = pcre_compile("([0-9]*|\\-[0-9]*)\\s(Quit)",PCRE_DOTALL,&error_re,&erroffset_re,0);
	if (!re_quit){
		fprintf(stdout,"Could not compile regex <Quit> (offset: %d), %s\n", erroffset_re, error_re);
		exit(1);
	}

	re_excp = pcre_compile("Query\\s+(select|set\\snames|show|rollback|start\\stransaction|commit|insert\\sinto\\sparts)",PCRE_DOTALL|PCRE_CASELESS,&error_re,&erroffset_re,0);
	if (!re_excp){
		fprintf(stdout,"Could not compile regex <Exception> (offset: %d), %s\n", erroffset_re, error_re);
		exit(1);
	}

	re_time = pcre_compile("^(\\d\\d\\d\\d\\d\\d\\s+\\d\\d:\\d\\d:\\d\\d)\\s",PCRE_DOTALL,&error_re,&erroffset_re,0);
    if (!re_time){
        fprintf(stdout,"Could not compile regex <Time> (offset: %d), %s\n", erroffset_re, error_re);
        exit(1);
    }
	
    wfd = fileno(stdout);

    if (buf == NULL) {
        if (fstat(wfd, &sbuf))
            err(1, "stdout");
	bsize = MAX(sbuf.st_blksize, 8196);
	if ((buf = malloc(bsize)) == NULL)
	    err(1, "malloc");
    }



    static char *line = NULL;
    static size_t lsize;
    struct stat lbuf;

    if (line == NULL) {
        if (fstat(wfd, &lbuf))
	    err(1, "stdout");
	lsize = MAX(lbuf.st_blksize, 134217728);
	if ((line = malloc(lsize)) == NULL)
	    err(1, "malloc");
    }

    static char *l_line = NULL;
    static size_t l_lsize;
    struct stat l_lbuf;

    if (l_line == NULL) {
        if (fstat(wfd, &l_lbuf))
             err(1, "stdout");
        l_lsize = MAX(l_lbuf.st_blksize, 134217728);
        if ((l_line = malloc(l_lsize)) == NULL)
             err(1, "malloc");
    }

    int i,j;
    size_t source_buf,t_line;
    source_buf = strlen(buf);
    t_line = strlen(line);

    char outstr[16];
    time_t now;
    struct tm *current; 
    struct tm {
    	int tm_sec; /* seconds after the minute - [0,59] */
    	int tm_min; /* minutes after the hour - [0,59] */
    	int tm_hour; /* hours since midnight - [0,23] */
    	int tm_mday; /* day of the month - [1,31] */
    	int tm_mon; /* months since January - [0,11] */
    	int tm_year; /* years since 1900 */
    	int tm_wday; /* days since Sunday - [0,6] */
    	int tm_yday; /* days since January 1 - [0,365] */
    	int tm_isdst; /* daylight savings time flag */
    };

	now = time(0);
    current = localtime(&now);
    strftime(outstr,16,"%y%m%d %H:%M:%S",current);


    char** arraych = (char**) malloc(25600*sizeof (char));
	if ( arraych == NULL)
		err(1, "malloc");		


    unsigned int arraynum[1000];
    for(i=0;i<1000;i++)
	arraynum[i]=0;
    unsigned int session_id = 0;

    while ((nr = read(rfd, buf, bsize)) != -1 && nr != 0) {
		if (line != NULL) {
		   free(line);
		   if (fstat(wfd, &lbuf))
				   err(1, "stdout");
			   lsize = MAX(lbuf.st_blksize, 134217728);
			   if ((line = malloc(lsize)) == NULL)
				   err(1, "malloc");
		   t_line = strlen(line);
		}
		for (off = 0; nr; nr -= nw, off += nw){
			for (i=0,j=0,nnw=0,tnw=0;i < nr ;i++,j++) {
				if ( buf[source_buf + i] == '\n' ) {
					if ( i + 1 == nr ){
						line[t_line + j] = buf[source_buf + i];
					}else if ( buf[source_buf + i + 1] == '\0' || ( (buf[source_buf + i + 1] == '\t' 
						&& buf[source_buf + i + 2] == '\t' ) && ( buf[source_buf + i + 3] != '\t' && buf[source_buf + i + 4] != '\t' ) )|| ( isdigit(buf[source_buf + i + 1]) && isdigit(buf[source_buf + i + 2]) ) ){
						
						line[t_line + j] = buf[source_buf + i];
					} else {

						
						line[t_line + j] = ' ';
					}

				} else {
					line[t_line + j] = buf[source_buf + i];
				}

				if (i == 8196 - 1 ){
					strncpy(l_line, line,strlen(line));
				}
				if (line[t_line + j] == '\n'){
					if (l_line[0] != '\0') {
						char * sss = malloc(strlen(line) + strlen(l_line)+1);
				        if (sss == NULL)
                        	err(1, "malloc");	
						sprintf(sss, "%s%s", l_line, line);
						memset(line,'\0',strlen(line));
						j = j + strlen(l_line);
						strcpy(line, sss);
						memset(l_line,'\0',strlen(l_line));
						free(sss);
					}
					line[t_line + j +1] = '\n';
					j=j+1;
					
					int count = 20;
					int vect_mess[20], vect_pre_authf[20], vect_authf[20], vect_con[20], vect_que[20], vect_quit[20],vect_excp[20],vect_time[20];
					rc_mess = 0;
					rc_mess=pcre_exec(re_mess, NULL, line, strlen(line), 0, 0, vect_mess, count);
					if (rc_mess>0){
						
						rc_pre_authf=0;
						rc_con=0;
						rc_que=0;
						rc_quit=0;
						rc_excp=0;
						rc_time=0;
						rc_pre_authf=pcre_exec(re_pre_authf, NULL, line, strlen(line), 0, 0, vect_pre_authf, count);
						
						rc_con=pcre_exec(re_con, NULL, line, strlen(line), 0, 0, vect_con, count);
						
						rc_que=pcre_exec(re_que, NULL, line, strlen(line), 0, 0, vect_que, count);
						
						rc_quit=pcre_exec(re_quit, NULL, line, strlen(line), 0, 0, vect_quit, count);
						
						rc_excp=pcre_exec(re_excp, NULL, line, strlen(line), 0, 0, vect_excp, count);
						
						rc_time=pcre_exec(re_time, NULL, line, strlen(line), 0, 0, vect_time, count);
						if (rc_time>0){
							char Current_time[16];
							char sourceCopy[strlen(line) + 1];	
							strcpy(sourceCopy, line);
							strncpy(Current_time,sourceCopy+vect_time[2],vect_time[3]-vect_time[2]);
							
							strcpy(outstr, Current_time);
							memset(Current_time,'\0',strlen(Current_time));	
							memset(sourceCopy,'\0',strlen(sourceCopy));
						}


						if (rc_pre_authf>0){
							rc_authf=pcre_exec(re_authf, NULL, line, strlen(line), 0, 0, vect_authf, count);
							if (rc_authf>0){
								unsigned int k = 0;
								char Group1[1024];
								char Group3[strlen(line) + 1];
								char sourceCopy[strlen(line) + 1];
								strcpy(sourceCopy, line);
								strncpy(Group1,sourceCopy+vect_authf[2],vect_authf[3]-vect_authf[2]);
								strncpy(Group3,sourceCopy+vect_authf[6],vect_authf[7]-vect_authf[6]);
								for(k = 0;k<1000;k++){
									if (arraynum[k] == atoi(Group1)){
										session_id = k;
										break;
									}
								}
								fprintf(stdout, "%s\tAuth_fail %s\n", outstr, Group3);

								memset(Group1,'\0',strlen(Group1));
								memset(Group3,'\0',strlen(Group3));
								memset(sourceCopy,'\0',strlen(sourceCopy));
								arraynum[session_id] = 0;
								memset(arraych[session_id],'\0',strlen(arraych[session_id]));
							}
						}
						else if (rc_con>0){
	                        unsigned int k = 0;
                            char Group1[1024];
                            char Group2[1024];
                            char sourceCopy[strlen(line) + 1];
                            strcpy(sourceCopy, line);
                            strncpy(Group1,sourceCopy+vect_con[2],vect_con[3]-vect_con[2]);
                            strncpy(Group2,sourceCopy+vect_con[6],vect_con[7]-vect_con[6]);
                            for(k = 0;k<1000;k++){
    	                        if (arraynum[k] == 0){
        	                        session_id = k;
                                    break;
                                }
                            }
							arraynum[session_id] = atoi(Group1);
							free(arraych[session_id]);
							arraych[session_id] = (char*) malloc(256*sizeof(char));
							if (arraych[session_id] == NULL)
	                            err(1, "malloc");
							strcpy(arraych[session_id], Group2);
							

                            memset(Group1,'\0',strlen(Group1));
                            memset(Group2,'\0',strlen(Group2));
                            memset(sourceCopy,'\0',strlen(sourceCopy));

						}
						else if (rc_que>0 && rc_excp<0){

							unsigned int k = 0;
							char Group1[1024];
							char Group2[1024];
							char Group3[strlen(line) + 1];
							char sourceCopy[strlen(line) + 1];

							strcpy(sourceCopy, line);
							strncpy(Group1,sourceCopy+vect_que[2],vect_que[3]-vect_que[2]);
							strncpy(Group2,sourceCopy+vect_que[4],vect_que[5]-vect_que[4]);
							strncpy(Group3,sourceCopy+vect_que[6],vect_que[1]);
							for(k = 0;k<1000;k++){
								if (arraynum[k] == atoi(Group1)){
									session_id = k;
									break;
								}
							}
							unsigned int p,r = 0;
							char clear_query[strlen(line) + 1];
							for (p=0,r=0;p<strlen(Group3)+1;p++)
							if (Group3[p] == ' ' && Group3[p + 1]== ' '){
							}
							else if (Group3[p] != '\t' && Group3[p] !='\n'){
								clear_query[r] = Group3[p];
								r = r + 1;
							}

							fprintf(stdout, "%s\t%s %s\t%s\n", outstr, arraych[session_id], Group2, clear_query);
								
							memset(Group1,'\0',strlen(Group1));
							memset(Group2,'\0',strlen(Group2));
							memset(Group3,'\0',strlen(Group3));
							memset(sourceCopy,'\0',strlen(sourceCopy));	
							memset(clear_query,'\0',strlen(clear_query));
						}
						else if (rc_quit>0){
                            unsigned int k = 0;
                            char Group1[1024];
                            char sourceCopy[strlen(line) + 1];

                            strcpy(sourceCopy, line);
                            strncpy(Group1,sourceCopy+vect_quit[2],vect_quit[3]-vect_quit[2]);
                            for(k = 0;k<1000;k++){
                                if (arraynum[k] == atoi(Group1)){
                                    session_id = k;
                                    break;
                                }
                            }
                            memset(Group1,'\0',strlen(Group1));
                            memset(sourceCopy,'\0',strlen(sourceCopy));

							arraynum[session_id] = 0;

						} 
					}
					memset(line,'\0',strlen(line));

					j=-1;
				}
			}
	
			nw = nr;
			memset(buf,'\0',strlen(buf));
		}
		if (nr < 0) {
			warn("%s", filename);
			rval = 1;
		}
	}
}
