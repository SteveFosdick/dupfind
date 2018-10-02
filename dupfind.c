/*
 * dupfind - find duplicate files and list or operate upon them.
 *
 * Copyright (C) 2003 Steve Fosdick.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307	 USA
 *
 *
 * There are three main phases to this program:
 *
 * The first phase builds the list of files to be searched for duplicates
 * by taking file names from the command line and/or reading stdin, and
 * recursing into sub-directories if told to.  This list of filenames is
 * stored in a binary tree for which the key is the filename and the
 * associated data is various information about the file, mostly from the
 * stat(2) system call.	 A tree is used rather than a simple list to make
 * sure the same filename is not entered more than once.
 *
 * The second phase steps though the list of files in the tree built by
 * phase one, calculates a message digest for each file (MD5) and* builds
 * a hash table with the message digest as the key and a linked list of
 * files having that digest as the value.
 *
 * The third phase steps through the hash table looking for groups of more
 * than one file sharing the same digest.  An exact match between files in
 * the group is checked with byte-by-byte comparison and the action
 * specified on the command line (list, link or delete) is applied.
 */

/* ANSI C Headers */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* GNU Headers */

#define G_LOG_DOMAIN progname
#include <glib.h>
#include <gcrypt.h>
#include <getopt.h>

/* Linux/Unix Headers */

#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

/* Flag values for command line options */

enum
{
    OPT_QUIET	  = 0x001,
    OPT_RECURSE	  = 0x002,
    OPT_SYMLINKS  = 0x004,
    OPT_HARDLINKS = 0x008,
    OPT_NOEMPTY	  = 0x010,
    OPT_SAMELINE  = 0x020,
    OPT_OMITFIRST = 0x040,
    OPT_SHOWSIZE  = 0x080,
    OPT_DELETE	  = 0x100,
    OPT_LINK	  = 0x200,
    OPT_STDIN	  = 0x400,
    OPT_VERBOSE	  = 0x800
};

/* Amount of data read at a time from files when calculating the message
 * digest or when comparing one file wit another.
 */

#define CHUNK_SIZE  8192

/* Which message digest algorith to use (from libgcrypt) */

#define DIGEST_ALGO GCRY_MD_MD5

/* Progname name/version - filled in by CVS */

static const char version[] = "$Id$";

/* The data stored about a file in the hash tables */

typedef struct
{
    char    *name;
    off_t   st_size;
    nlink_t st_nlink;
    mode_t  st_mode;
    dev_t   st_dev;
    ino_t   st_ino;
} file_t;

/* The value type for the second hash table, keyed by message digest */

typedef struct
{
    gint  nfile;
    GList *files;
} file_list_t;

/* A value type used to implement the 'delete' action. */

typedef struct
{
    file_t *file;
    char   keep;
} delete_t;

/* user data passed to tree foreach. */

typedef struct
{
    GHashTable *hash;
    GChecksum  *digest;
} tree_foreach_t;

/* Bit-map of command line options */

static unsigned long options;

/* Program named used in  error messages */

static const char *progname;

/* Which stat(2) system call to use - if we want to follow symbolic
 * links we use stat(2) which follows the link, otherwise we use lstat(2)
 * which reports about the link rather than the file linked to. */

static int (*stat_func)(const char *name, struct stat *buf) = lstat;

/* Function called during phase one for each file system object being
 * worked on - it works out whether it is a file/directory etc. and
 * either adds it to the list or recusrses into it. */

static int do_fsobj(GTree *file_tree, const char *name)
{
    int		  status;
    struct stat	  stbuf;
    file_t	  *fp;
    DIR		  *dp;
    struct dirent *dent;
    const char	  *dname;
    char	  *path;

    if (stat_func(name, &stbuf) == 0)
    {
	status = 0;
	if (S_ISREG(stbuf.st_mode))
	{
	    if (stbuf.st_size > 0 || !(options & OPT_NOEMPTY))
	    {
		if (g_tree_lookup(file_tree, name))
		{
		    if (!(options & OPT_QUIET))
			g_warning("filename '%s' alreday seen", name);
		}
		else
		{
		    fp = g_malloc(sizeof(file_t));
		    fp->name = g_strdup(name);
		    fp->st_size = stbuf.st_size;
		    fp->st_nlink = stbuf.st_nlink;
		    fp->st_mode = stbuf.st_mode;
		    fp->st_dev = stbuf.st_dev;
		    fp->st_ino = stbuf.st_ino;
		    g_tree_insert(file_tree, fp->name, fp);
		}
	    }
	}
	else if (S_ISDIR(stbuf.st_mode))
	{
	    if (options & OPT_RECURSE)
	    {
		if ((dp = opendir(name)))
		{
		    while ((dent = readdir(dp)))
		    {
			dname = dent->d_name;
			if (dname[0] != '.' ||
			    (dname[1] != '.' && dname[1] != '\0'))
			{
			    path = g_strconcat(name, "/", dent->d_name, NULL);
			    status += do_fsobj(file_tree, path);
			    g_free(path);
			}
		    }
		    closedir(dp);
		}
		else
		{
		    g_warning("unable to read directory '%s' - %m", name);
		    status = 1;
		}
	    }
	    else
		g_warning("%s is a directory - ignored", name);
	}
    }
    else
    {
	g_warning("unable to stat '%s' - %m", name);
	status = 1;
    }
    return status;
}

/* Function called during phase one to read filenames from stdin
 * and add them to the list. */

static int do_stdin(GTree *file_tree)
{
    int	 status = 0;
    char name[1024];
    char *ptr;

    while (fgets(name, sizeof(name), stdin) != NULL)
    {
	if ((ptr = strchr(name, '\n')))
	    *ptr = '\0';
	status += do_fsobj(file_tree, name);
    }
    return status;
}

/* Function called during phase two by g_hash_table_foreach for each
 * file in the first hashtable, keyed by filename */

static gboolean file_foreach(gpointer key, gpointer value, gpointer udata)
{
    char	   *file = key;
    const char	   *digest_txt;
    char           *digest_cpy;
    tree_foreach_t *fdata = udata;
    file_list_t    *file_list;
    int            fd;
    ssize_t        nbytes;
    unsigned char  buf[8192];

    if ((fd = open(file, O_RDONLY, 0)) >= 0) {
        while ((nbytes = read(fd, buf, sizeof(buf))) > 0)
            g_checksum_update(fdata->digest, buf, nbytes);
        close(fd);
        if ((digest_txt = g_checksum_get_string(fdata->digest))) {
            if ((file_list = g_hash_table_lookup(fdata->hash, digest_txt))) {
                file_list->nfile++;
                file_list->files = g_list_append(file_list->files, value);
            }
            else {
                digest_cpy = g_strdup(digest_txt);
                file_list = g_malloc(sizeof(file_list_t));
                file_list->nfile = 1;
                file_list->files = g_list_append(NULL, value);
                g_hash_table_insert(fdata->hash, digest_cpy, file_list);
            }
        }
        else
            g_warning("digest calculation failed on file '%s'", file);
        g_checksum_reset(fdata->digest);
    }
    else
	g_warning("unable to open file '%s' for reading - %m", file);
    return FALSE;
}

/* Comparison function used during phase three, called by g_list_sort
 * and used to sort a list of files by the number of hard links - this
 * is need for the correct handling of groups of files having the same
 * digest where some are hard-linked together and others are not. */

static gint sort_compare(gconstpointer a, gconstpointer b)
{
    const file_t *fa = a;
    const file_t *fb = b;
    gint res;

    if ((res = fb->st_nlink - fa->st_nlink) == 0)
	res = strcmp(fa->name, fb->name);
    return res;
}

/* Function used during phase three, it takes a list of files and
 * returns another list which contains only one file from any set
 * that are hard-linked together */

static GList *filter_links(GList *list)
{
    GList  *ptr;
    file_t *fp1, *fp2;
    int	   found;

    if (list == NULL)
	return NULL;

    GList *new_list = g_list_append(NULL, list->data);
    while ((list = list->next))
    {
	fp1 = list->data;
	found = 0;
	for (ptr = new_list; ptr; ptr = ptr->next)
	{
	    fp2 = ptr->data;
	    if (fp2->st_dev == fp1->st_dev &&
		fp2->st_ino == fp1->st_ino)
	    {
		found = 1;
		break;
	    }
	}
	if (found == 0)
	    new_list = g_list_append(new_list, fp1);
    }
    return new_list;
}

/* Function used during phase three, to do a byte-by-byte comparison of
 * two files - returns 1 is they are the same, 0 otherwise. */

static int compare_files(file_t *file1, file_t *file2)
{
    const char *name1, *name2;
    int	       fd1, fd2;
    char       buf1[CHUNK_SIZE],buf2[CHUNK_SIZE];
    ssize_t    nb1, nb2;
    int	       status;

    status = 0;
    name1 = file1->name;
    if ((fd1 = open(name1, O_RDONLY)) != -1)
    {
	name2 = file2->name;
	if ((fd2 = open(name2, O_RDONLY)) != -1)
	{
	    do
	    {
		if ((nb1 = read(fd1, buf1, sizeof(buf1))) == -1)
		{
		    g_critical("read error on file '%s' - %m", name1);
		    break;
		}
		if ((nb2 = read(fd2, buf2, sizeof(buf2))) == -1)
		{
		    g_critical("read error on file '%s' - %m", name2);
		    break;
		}
		if (nb1 == 0 && nb2 == 0)
		{
		    status = 1;
		    break;
		}
	    }
	    while (nb1 == nb2 && memcmp(buf1, buf2, nb1) == 0);
	    close(fd2);
	}
	else
	    g_critical("unable to open file '%s' for reading - %m", name2);
	close(fd1);
    }
    else
	g_critical("unable to open file '%s' for reading - %m", name1);
    return status;
}

/* Function used during phase three.  This function makes the second file,
 * called the slave, a hard link to the first, called the master. */

static void link_pair(file_t *master, file_t *slave)
{
    if (unlink(slave->name) == 0)
    {
	if (link(master->name, slave->name) == -1)
	    g_warning("unable to link '%s' to '%s' - %m",
		      master->name, slave->name);
    }
    else
	g_warning("unable to unlink '%s' - %m", slave->name);
}

/* Function used during phase three to implement the interactive deletion
 * of some files from a group known to have the same contents. */

static void delete_files(const char *digest, file_t *master, GList *list)
{
    GList      *delete_list;
    GList      *ptr;
    delete_t   *elem;
    int	       print_list;
    int	       i;
    char       buf[20];
    const char *name;

    elem = g_malloc(sizeof(delete_t));
    elem->file = master;
    elem->keep = 1;
    delete_list = g_list_append(NULL, elem);

    for (ptr = list; ptr; ptr = ptr->next)
    {
	elem = g_malloc(sizeof(delete_t));
	elem->file = ptr->data;
	elem->keep = 0;
	delete_list = g_list_append(delete_list, elem);
    }

    for (print_list = 1; ;)
    {
	if (print_list)
	{
	    printf("\nDisposition of files with digest %s\n\n", digest);
	    i = 1;
	    for (ptr = delete_list; ptr; ptr = ptr->next)
	    {
		elem = ptr->data;
		printf("%5d %c %s (%ld links)\n",
		       i++, elem->keep ? '*' : ' ',
                       elem->file->name, elem->file->st_nlink);
	    }
	    fputs("\nFiles marked (*) will be kept - these reset deleted\n"
		  "To toggle a file's status type its number\n"
		  "Type 'go' to go ahead with the delete\n", stdout);
	    print_list = 0;
	}
	fputs("\n> ", stdout);
	if (fgets(buf, sizeof(buf), stdin) == NULL)
	{
	    fputs("*** EOF *** no action taken\n", stdout);
	    break;
	}
	if (strncmp(buf, "go", 2) == 0)
	{
	    for (ptr = delete_list; ptr; ptr = ptr->next)
	    {
		elem = ptr->data;
		if (elem->keep == 0)
		{
		    name = elem->file->name;
		    if (unlink(name) == 0)
			printf("%s deleted\n", name);
		    else
			g_warning("unable to delete '%s' - %m", name);
		}
	    }
	    break;
	}
	if ((i = atoi(buf)) > 0)
	{
	    if ((elem = g_list_nth_data(delete_list, i - 1)))
	    {
		elem->keep = 1 - elem->keep;
		print_list = 1;
	    }
	    else
		printf("no file number %d\n", i);
	}
	else
	    fputs("invalid input - please type a number or 'go'\n", stdout);
    }
    for (ptr = delete_list; ptr; ptr = ptr->next)
	g_free(ptr->data);
    g_list_free(delete_list);
}

/* Function used during phase three to list a single group of files
 * known to have the same contents. */

static void list_files(file_t *master, GList *list)
{
    int fs = (options & OPT_SAMELINE) ? ' ' : '\n';
    file_t *fp;

    if (!(options & OPT_OMITFIRST))
    {
	if (options & OPT_SHOWSIZE)
	    printf("%s (%ld)%c", master->name, master->st_size, fs);
	else
	    printf("%s%c", master->name, fs);
    }
    while (list)
    {
	fp = list->data;
	if (options & OPT_SHOWSIZE)
	    printf("%s (%ld)%c", fp->name, fp->st_size, fs);
	else
	    printf("%s%c", fp->name, fs);
	list = list->next;
    }
    fputc('\n', stdout);
}

/* Function called during phase two by g_hash_table_foreach for each
 * group of files having the same message digest.  This function checks
 * if the files are really the same and calls the appropriate action
 * function depending on what was specified on the command line. */

static void digest_foreach(gpointer key, gpointer value, gpointer udata)
{
    file_list_t *file_list = value;
    GList	*search_list, *good_list, *bad_list;
    int		good_count;
    file_t	*master;

    if (file_list->nfile > 1)
    {
	search_list = g_list_sort(file_list->files, sort_compare);
	if (!(options & OPT_HARDLINKS))
	    search_list = filter_links(search_list);
	while (search_list)
	{
	    good_list = bad_list = NULL;
	    good_count = 0;
	    master = search_list->data;
	    while ((search_list = search_list->next))
	    {
		if (compare_files(master, search_list->data))
		{
		    if (options & OPT_LINK)
			link_pair(master, search_list->data);
		    else
		    {
			good_list = g_list_append(good_list,search_list->data);
			good_count++;
		    }
		}
		else
		    bad_list = g_list_append(bad_list, search_list->data);
	    }
	    if (good_count > 0)
	    {
		if (options & OPT_DELETE)
		    delete_files(key, master, good_list);
		else
		    list_files(master, good_list);
		g_list_free(good_list);
	    }
	    g_list_free(search_list);
	    search_list = bad_list;
	}
    }
}

static const char help_text[] =
    "\nUsage: dupfind [options] [ <file|dirrectory> ... ]\n"
    "\n"
    "  -q --quiet	disable progress indicator/messages\n"
    "  -r --recurse	include files residing in subdirectories\n"
    "  -s --symlinks	follow symlinks\n"
    "  -H --hardlinks	normally, when two or more files point to the same\n"
    "			disk area they are treated as non-duplicates; this\n"
    "			option will change this behavior\n"
    "  -n --noempty	exclude zero-length files from consideration\n"
    "  -1 --sameline	list each set of matches on a single line\n"
    "  -f --omitfirst	omit the first file in each set of matches\n"
    "  -S --size	show size of duplicate files\n"
    "  -d --delete	for each set of duplicate files prompt user for\n"
    "			files to preserve and delete all others\n"
    "  -l --link	for each set of duplicate files make all the\n"
    "			filenames hard links to the same disk storage\n"
    "  -i -- stdin	read file names from stdin as well as processing\n"
    "			any specified on the command line\n"
    "  -v --verbose	show progress messages\n"
    "  -V --version	display dupfind version\n"
    "  -h --help	display this help message\n\n";

int main(int argc, char **argv)
{
    char           *ptr;
    int	           opt;
    GTree          *file_tree;
    tree_foreach_t foreach_data;
    int	           status;

    static struct option long_options[] =
    {
	{ "quiet",     0, 0, 'q' },
	{ "recurse",   0, 0, 'r' },
	{ "symlinks",  0, 0, 's' },
	{ "hardlinks", 0, 0, 'H' },
	{ "noempty",   0, 0, 'n' },
	{ "sameline",  0, 0, '1' },
	{ "omitfirst", 0, 0, 'f' },
	{ "size",      0, 0, 'S' },
	{ "delete",    0, 0, 'd' },
	{ "link",      0, 0, 'l' },
	{ "stdin",     0, 0, 'i' },
	{ "verbose",   0, 0, 'v' },
	{ "version",   0, 0, 'V' },
	{ "help",      0, 0, 'h' },
	{ 0,	       0, 0, 0	 }
    };

    if ((ptr = strrchr(argv[0], '/')))
	argv[0] = ptr+1;
    progname = argv[0];

    while ((opt = getopt_long(argc, argv, "rqsHn1fSdlivh", long_options, NULL)) != EOF)
    {
	switch (opt)
	{
	case 'q':
	    options |= OPT_QUIET;
	    break;
	case 'r':
	    options |= OPT_RECURSE;
	    break;
	case 's':
	    options |= OPT_SYMLINKS;
	    break;
	case 'H':
	    options |= OPT_HARDLINKS;
	    break;
	case 'n':
	    options |= OPT_NOEMPTY;
	    break;
	case '1':
	    options |= OPT_SAMELINE;
	    break;
	case 'f':
	    options |= OPT_OMITFIRST;
	    break;
	case 'S':
	    options |= OPT_SHOWSIZE;
	    break;
	case 'd':
	    options |= OPT_DELETE;
	    break;
	case 'l':
	    options |= OPT_LINK;
	    break;
	case 'i':
	    options |= OPT_STDIN;
	    break;
	case 'v':
	    options |= OPT_VERBOSE;
	    break;
	case 'V':
	    fputs(version, stderr);
	    return 0;
	case 'h':
	    fputs(help_text, stderr);
	    return 0;
	default:
	    g_critical("bad command line args - try 'dupfind --help'");
	    return 1;
	}
    }
    if ((options & (OPT_DELETE|OPT_LINK)) == (OPT_DELETE|OPT_LINK))
    {
	g_critical("link and delete are mutually exclusive");
	return 1;
    }
    if (optind == argc && !(options & OPT_STDIN))
    {
	g_critical("nothing to do - try 'dupfind --help'");
	return 1;
    }
    if (options & OPT_SYMLINKS)
	stat_func = stat;
    status = 0;

    /* Phase one - build the file list */

    if (options & OPT_VERBOSE)
	g_log(NULL, G_LOG_LEVEL_INFO, "building file list");
    file_tree = g_tree_new((GCompareFunc)strcmp);
    while (optind < argc)
	status += do_fsobj(file_tree, argv[optind++]);
    if (options & OPT_STDIN)
	status += do_stdin(file_tree);

    /* Phase two - group files by message digest */

    if (options & OPT_VERBOSE)
	g_log(NULL, G_LOG_LEVEL_INFO, "calculating digests");
    foreach_data.hash = g_hash_table_new(g_str_hash, g_str_equal);
    foreach_data.digest =g_checksum_new(G_CHECKSUM_MD5);
    g_tree_foreach(file_tree, file_foreach, &foreach_data);

    /* Phase three - check for exact match and carry out actions */

    if (options & OPT_VERBOSE)
	g_log(NULL, G_LOG_LEVEL_INFO, "performing required actions");
    g_hash_table_foreach(foreach_data.hash, digest_foreach, NULL);
    return status;
}
