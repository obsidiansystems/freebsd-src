/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2008 Ed Schouten <ed@FreeBSD.org>
 * All rights reserved.
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
 */

#include "namespace.h"
#include <sys/param.h>
#include <sys/procctl.h>
#include <sys/procdesc.h>
#include <sys/queue.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#include <sched.h>
#include <spawn.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "un-namespace.h"
#include "libc_private.h"

struct __posix_spawnattr {
	short			sa_flags;
	pid_t			sa_pgroup;
	struct sched_param	sa_schedparam;
	int			sa_schedpolicy;
	sigset_t		sa_sigdefault;
	sigset_t		sa_sigmask;
	int			sa_execfd;
	int			*sa_pdrfork_fdp;
	int			sa_pdflags;
};

struct __posix_spawn_file_actions {
	STAILQ_HEAD(, __posix_spawn_file_actions_entry) fa_list;
};

typedef struct __posix_spawn_file_actions_entry {
	STAILQ_ENTRY(__posix_spawn_file_actions_entry) fae_list;
	enum {
		FAE_OPEN,
		FAE_DUP2,
		FAE_CLOSE,
		FAE_CHDIR,
		FAE_FCHDIR,
		FAE_CLOSEFROM,
	} fae_action;

	int fae_fildes;
	union {
		struct {
			char *path;
#define fae_path	fae_data.open.path
			int oflag;
#define fae_oflag	fae_data.open.oflag
			mode_t mode;
#define fae_mode	fae_data.open.mode
		} open;
		struct {
			int newfildes;
#define fae_newfildes	fae_data.dup2.newfildes
		} dup2;
	} fae_data;
} posix_spawn_file_actions_entry_t;

/*
 * Spawn routines.
 *
 * These work through the embryonic-process interface --- pdrfork(2) with
 * RFEMBRYO to create a process, the pdset* calls to configure it, and
 * pdexec(2) to give it a program and run it --- rather than vfork(2).
 *
 * The traditional implementation ran a child under vfork(2): the child
 * shared the parent's address space, mutated *itself* into the requested
 * state, and then exec(2)d.  That is why it had to hand-allocate a stack,
 * avoid the dynamic linker, and pass the exec error back through shared
 * memory.
 *
 * Here nothing runs in the child.  The embryo is created empty, configured
 * from the outside, and then pdexec(2) loads its program and starts it in
 * one step, reporting any load failure straight to the caller.  Because a
 * failed pdexec(2) destroys the process, each executable a posix_spawnp(3)
 * PATH search tries gets its own embryo --- the point at which the shape
 * comes back around to the traditional per-child model.
 *
 * The descriptor table is the interesting part.  An embryo starts empty and
 * can only be added to (there is deliberately no way to remove a descriptor
 * from another process's table), whereas POSIX describes the child as
 * inheriting everything and then having file actions applied to it.  So
 * rather than replay the actions, we *simulate* them here to work out which
 * descriptors the child should end up with, and then install exactly those:
 * spawn_fdmap_apply() builds the map, spawn_fdmap_install() realises it with
 * pdsetfd(2) for individual descriptors and pdsetfdrange(2) for the runs
 * that are merely inherited.
 */

#define	SPAWN_FD_INHERIT	(-1)	/* parent's descriptor of same number */
#define	SPAWN_FD_CLOSED		(-2)	/* explicitly closed by a file action */

struct spawn_fdent {
	int	fe_child;		/* descriptor number in the child */
	int	fe_src;			/* parent fd, or SPAWN_FD_CLOSED */
};

struct spawn_fdmap {
	struct spawn_fdent *fm_ent;
	size_t	fm_cnt;
	size_t	fm_max;
	int	fm_closefrom;		/* everything >= this is closed, or -1 */
	int	fm_cwd;			/* dir the child should start in */
	bool	fm_cwd_set;		/* ... if a chdir action asked for one */
	int	*fm_tmp;		/* parent fds we opened, to close later */
	size_t	fm_tmpcnt;
	size_t	fm_tmpmax;
};

static void
spawn_fdmap_init(struct spawn_fdmap *fm)
{
	memset(fm, 0, sizeof(*fm));
	fm->fm_closefrom = -1;
	fm->fm_cwd = AT_FDCWD;
}

static void
spawn_fdmap_fini(struct spawn_fdmap *fm)
{
	size_t i;

	for (i = 0; i < fm->fm_tmpcnt; i++)
		(void)_close(fm->fm_tmp[i]);
	free(fm->fm_tmp);
	free(fm->fm_ent);
}

/*
 * Record a descriptor we opened on the child's behalf, to close on the way
 * out.
 */
static int
spawn_fdmap_tmp(struct spawn_fdmap *fm, int fd)
{
	int *n;

	if (fm->fm_tmpcnt == fm->fm_tmpmax) {
		fm->fm_tmpmax = fm->fm_tmpmax != 0 ? fm->fm_tmpmax * 2 : 8;
		n = reallocarray(fm->fm_tmp, fm->fm_tmpmax, sizeof(*n));
		if (n == NULL)
			return (ENOMEM);
		fm->fm_tmp = n;
	}
	fm->fm_tmp[fm->fm_tmpcnt++] = fd;
	return (0);
}

static struct spawn_fdent *
spawn_fdmap_find(struct spawn_fdmap *fm, int child)
{
	size_t i;

	for (i = 0; i < fm->fm_cnt; i++) {
		if (fm->fm_ent[i].fe_child == child)
			return (&fm->fm_ent[i]);
	}
	return (NULL);
}

static int
spawn_fdmap_set(struct spawn_fdmap *fm, int child, int src)
{
	struct spawn_fdent *e, *n;

	e = spawn_fdmap_find(fm, child);
	if (e != NULL) {
		e->fe_src = src;
		return (0);
	}
	if (fm->fm_cnt == fm->fm_max) {
		fm->fm_max = fm->fm_max != 0 ? fm->fm_max * 2 : 8;
		n = reallocarray(fm->fm_ent, fm->fm_max, sizeof(*n));
		if (n == NULL)
			return (ENOMEM);
		fm->fm_ent = n;
	}
	fm->fm_ent[fm->fm_cnt].fe_child = child;
	fm->fm_ent[fm->fm_cnt].fe_src = src;
	fm->fm_cnt++;
	return (0);
}

/*
 * What would the child's descriptor `child' refer to at this point in the
 * sequence?  Either something an earlier action put there, or -- absent any
 * action -- the parent's descriptor of the same number.
 */
static int
spawn_fdmap_resolve(struct spawn_fdmap *fm, int child)
{
	struct spawn_fdent *e;

	e = spawn_fdmap_find(fm, child);
	if (e != NULL)
		return (e->fe_src);
	if (fm->fm_closefrom >= 0 && child >= fm->fm_closefrom)
		return (SPAWN_FD_CLOSED);
	return (SPAWN_FD_INHERIT);
}

/*
 * Simulate the file actions in order.  Opens are performed here, in the
 * parent: the child cannot run code, and doing it here gives exactly the
 * credentials POSIX specifies for a file action (those of the caller, before
 * the image was loaded).  The cost is one spare descriptor at a time.
 */
static int
spawn_fdmap_apply(struct spawn_fdmap *fm, const posix_spawn_file_actions_t fa)
{
	posix_spawn_file_actions_entry_t *fae;
	int error, fd, src;

	STAILQ_FOREACH(fae, &fa->fa_list, fae_list) {
		switch (fae->fae_action) {
		case FAE_OPEN:
			/*
			 * Relative to whatever an earlier chdir action asked
			 * for, since in the traditional model the open would
			 * have happened in the child, after it moved.
			 */
			fd = _openat(fm->fm_cwd, fae->fae_path,
			    fae->fae_oflag | O_CLOEXEC, fae->fae_mode);
			if (fd < 0)
				return (errno);
			error = spawn_fdmap_tmp(fm, fd);
			if (error != 0)
				return (error);
			error = spawn_fdmap_set(fm, fae->fae_fildes, fd);
			if (error != 0)
				return (error);
			break;
		case FAE_DUP2:
			/*
			 * dup2(2)'s source is a descriptor *in the child*, so
			 * it may itself have been established by an earlier
			 * action.
			 */
			src = spawn_fdmap_resolve(fm, fae->fae_fildes);
			if (src == SPAWN_FD_CLOSED)
				return (EBADF);
			if (src == SPAWN_FD_INHERIT)
				src = fae->fae_fildes;
			error = spawn_fdmap_set(fm, fae->fae_newfildes, src);
			if (error != 0)
				return (error);
			break;
		case FAE_CLOSE:
			error = spawn_fdmap_set(fm, fae->fae_fildes,
			    SPAWN_FD_CLOSED);
			if (error != 0)
				return (error);
			break;
		case FAE_CLOSEFROM:
			/*
			 * Drop anything at or above the watermark that an
			 * earlier action had set, then let the watermark cover
			 * the rest, including inherited descriptors.
			 */
			for (size_t i = 0; i < fm->fm_cnt; i++) {
				if (fm->fm_ent[i].fe_child >= fae->fae_fildes)
					fm->fm_ent[i].fe_src = SPAWN_FD_CLOSED;
			}
			if (fm->fm_closefrom < 0 ||
			    fae->fae_fildes < fm->fm_closefrom)
				fm->fm_closefrom = fae->fae_fildes;
			break;
		case FAE_CHDIR:
			fd = _openat(fm->fm_cwd, fae->fae_path,
			    O_RDONLY | O_DIRECTORY | O_CLOEXEC);
			if (fd < 0)
				return (errno);
			error = spawn_fdmap_tmp(fm, fd);
			if (error != 0)
				return (error);
			fm->fm_cwd = fd;
			fm->fm_cwd_set = true;
			break;
		case FAE_FCHDIR:
			/*
			 * As with dup2, the descriptor names the child's
			 * table, so it may have been established by an
			 * earlier action.
			 */
			src = spawn_fdmap_resolve(fm, fae->fae_fildes);
			if (src == SPAWN_FD_CLOSED)
				return (EBADF);
			if (src == SPAWN_FD_INHERIT)
				src = fae->fae_fildes;
			fm->fm_cwd = src;
			fm->fm_cwd_set = true;
			break;
		}
	}
	return (0);
}

/*
 * Realise the map in the embryo: named descriptors individually, and the
 * runs between them -- those the child merely inherits -- in bulk.
 */
static int
spawn_fdmap_install(struct spawn_fdmap *fm, int procfd)
{
	size_t i, j;
	int error, lo, hi, tmp;

	/* Sort by child descriptor so the inherited runs are easy to find. */
	for (i = 1; i < fm->fm_cnt; i++) {
		for (j = i; j > 0 && fm->fm_ent[j - 1].fe_child >
		    fm->fm_ent[j].fe_child; j--) {
			struct spawn_fdent t = fm->fm_ent[j - 1];
			fm->fm_ent[j - 1] = fm->fm_ent[j];
			fm->fm_ent[j] = t;
		}
	}

	for (i = 0; i < fm->fm_cnt; i++) {
		if (fm->fm_ent[i].fe_src < 0)
			continue;
		if (pdsetfd(procfd, fm->fm_ent[i].fe_child,
		    fm->fm_ent[i].fe_src) != 0)
			return (errno);
	}

	/*
	 * Copy the inherited descriptors: every range not named by an action,
	 * up to the closefrom watermark.  pdsetfdrange(2) skips gaps as well
	 * as close-on-fork and close-on-exec descriptors, so what arrives is
	 * what would have survived a fork(2) followed by an execve(2).
	 */
	if (fm->fm_cwd_set && pdchdir(procfd, fm->fm_cwd) != 0)
		return (errno);

	lo = 0;
	for (i = 0; i <= fm->fm_cnt; i++) {
		if (i < fm->fm_cnt)
			hi = fm->fm_ent[i].fe_child - 1;
		else
			hi = INT_MAX;
		if (fm->fm_closefrom >= 0 && hi >= fm->fm_closefrom)
			hi = fm->fm_closefrom - 1;
		if (hi >= lo) {
			error = pdsetfdrange(procfd, (u_int)lo, (u_int)hi, 0);
			if (error != 0)
				return (errno);
		}
		if (i < fm->fm_cnt) {
			tmp = fm->fm_ent[i].fe_child + 1;
			lo = tmp > lo ? tmp : lo;
		}
		if (fm->fm_closefrom >= 0 && lo >= fm->fm_closefrom)
			break;
	}
	return (0);
}

/*
 * Scheduling policy and parameters, as POSIX_SPAWN_SETSCHEDULER and
 * POSIX_SPAWN_SETSCHEDPARAM ask.
 *
 * The two are alternatives rather than independent: naming a policy carries
 * parameters with it, so SETSCHEDULER subsumes SETSCHEDPARAM.
 */
static int
spawn_pd_sched(int procfd, const posix_spawnattr_t *sa)
{

	if (sa == NULL)
		return (0);
	if (((*sa)->sa_flags & POSIX_SPAWN_SETSCHEDULER) != 0) {
		if (pdsetscheduler(procfd, (*sa)->sa_schedpolicy,
		    &(*sa)->sa_schedparam) != 0)
			return (errno);
	} else if (((*sa)->sa_flags & POSIX_SPAWN_SETSCHEDPARAM) != 0) {
		if (pdsetschedparam(procfd, &(*sa)->sa_schedparam) != 0)
			return (errno);
	}
	return (0);
}

/*
 * Place the new process in a process group, as POSIX_SPAWN_SETPGROUP asks.
 *
 * A pgroup of zero means a new group under the child's own pid, which is
 * what pdsetpgid(2) does with a zero argument, so it passes straight
 * through.
 */
static int
spawn_pd_pgroup(int procfd, const posix_spawnattr_t *sa)
{

	if (sa == NULL || ((*sa)->sa_flags & POSIX_SPAWN_SETPGROUP) == 0)
		return (0);
	if (pdsetpgid(procfd, (*sa)->sa_pgroup) != 0)
		return (errno);
	return (0);
}

/*
 * Attributes reached through procctl(2).  Addressing it by P_PROCDESC rather
 * than by pid keeps the operation usable in capability mode and lets it name
 * a process that has not been started, neither of which a pid can do.
 */
static int
spawn_pd_procctl(int procfd, const posix_spawnattr_t *sa)
{
	int aslr;

	if (sa == NULL)
		return (0);
	if (((*sa)->sa_flags & POSIX_SPAWN_DISABLE_ASLR_NP) != 0) {
		aslr = PROC_ASLR_FORCE_DISABLE;
		if (procctl(P_PROCDESC, procfd, PROC_ASLR_CTL, &aslr) != 0)
			return (errno);
	}
	return (0);
}

/*
 * Reproduce the signal state execve(2) would have left behind.
 *
 * A newly created embryo blocks nothing and has every signal at its
 * default disposition, so both halves have to be asked for: the mask, and
 * the set of signals that were ignored.  POSIX says the child inherits the
 * caller's mask unless POSIX_SPAWN_SETSIGMASK, and keeps the caller's
 * ignored signals except those named by POSIX_SPAWN_SETSIGDEF.
 */
static int
spawn_pd_signals(int procfd, const posix_spawnattr_t *sa)
{
	struct sigaction oact;
	sigset_t mask, ign;
	int i;

	if (sa != NULL && ((*sa)->sa_flags & POSIX_SPAWN_SETSIGMASK) != 0)
		mask = (*sa)->sa_sigmask;
	else if (_sigprocmask(SIG_BLOCK, NULL, &mask) != 0)
		return (errno);
	if (pdsetsigmask(procfd, &mask) != 0)
		return (errno);

	sigemptyset(&ign);
	for (i = 1; i <= _SIG_MAXSIG; i++) {
		if (sa != NULL &&
		    ((*sa)->sa_flags & POSIX_SPAWN_SETSIGDEF) != 0 &&
		    sigismember(&(*sa)->sa_sigdefault, i))
			continue;
		if (_sigaction(i, NULL, &oact) != 0)
			continue;	/* not a valid signal number */
		if (oact.sa_handler == SIG_IGN)
			sigaddset(&ign, i);
	}
	if (pdsetsigign(procfd, &ign) != 0)
		return (errno);
	return (0);
}

/*
 * Outcome of one attempt to create the process from a candidate path.  The
 * distinction that matters during a PATH walk is whether the failure was a
 * property of the path tried (keep looking) or of the request as a whole
 * (stop, and report it).
 */
enum spawn_pd_try {
	SPAWN_PD_OK,		/* created; *procfdp is the descriptor */
	SPAWN_PD_NEXT,		/* this path did not work; try the next */
	SPAWN_PD_FAIL,		/* terminal; *errp is the error */
};

/*
 * Context threaded through the PATH walk: the file actions and attributes
 * to apply to each embryo, where to report the pid, and the pdrfork(2)
 * flags.
 */
struct spawn_pd_ctx {
	const posix_spawn_file_actions_t *fa;
	const posix_spawnattr_t *sa;
	pid_t *pid;
	int pdflags;
};

/*
 * Apply the file actions and attributes to a freshly created embryo, in the
 * order posix_spawn(3) prescribes, before it is given a program.
 *
 * POSIX_SPAWN_RESETIDS must happen here, before pdexec(2) loads the image,
 * because the image's access check is made against the resulting identity.
 */
static int
spawn_pd_configure(int procfd, const struct spawn_pd_ctx *ctx)
{
	struct spawn_fdmap fm;
	int error;

	/*
	 * The same attributes in the same order as the vfork(2)-based
	 * process_spawnattr() applied to itself: process group, scheduling,
	 * real ids, signals, then ASLR.
	 */
	error = spawn_pd_pgroup(procfd, ctx->sa);
	if (error == 0)
		error = spawn_pd_sched(procfd, ctx->sa);
	if (error == 0 && ctx->sa != NULL &&
	    ((*ctx->sa)->sa_flags & POSIX_SPAWN_RESETIDS) != 0 &&
	    pdresetids(procfd) != 0)
		error = errno;
	if (error == 0)
		error = spawn_pd_signals(procfd, ctx->sa);
	if (error == 0)
		error = spawn_pd_procctl(procfd, ctx->sa);
	if (error == 0) {
		spawn_fdmap_init(&fm);
		if (ctx->fa != NULL)
			error = spawn_fdmap_apply(&fm, *ctx->fa);
		if (error == 0)
			error = spawn_fdmap_install(&fm, procfd);
		spawn_fdmap_fini(&fm);
	}
	return (error);
}

/*
 * Create an embryo, configure it, and run one executable in it -- from a
 * path, or from an already-open descriptor when the caller supplied one.
 *
 * pdexec(2) loads the image and starts it in a single step, and a failure
 * to load destroys the process, since it never ran.  Each executable tried
 * therefore gets its own embryo, much as the traditional vfork(2)-based
 * posix_spawn(3) forks a child per attempt.
 */
static enum spawn_pd_try
spawn_pd_create(const struct spawn_pd_ctx *ctx, const char *path, int execfd,
    char * const argv[], char * const envp[], int *procfdp, int *errp)
{
	char **av, **ev;
	bool ownexecfd;
	int procfd, rc, serrno;

	/*
	 * When the caller did not supply a descriptor, open the path -- both to
	 * report a missing or unreadable file synchronously (so posix_spawnp(3)
	 * moves to the next PATH element) and to steer the ENOEXEC fallback.
	 * The open is only a probe: the exec below runs by path, not by this
	 * descriptor, so the image is not handed a copy of its own executable.
	 */
	ownexecfd = false;
	if (execfd == -1) {
		execfd = _open(path, O_RDONLY | O_CLOEXEC);
		if (execfd < 0) {
			*errp = errno;
			return (SPAWN_PD_NEXT);
		}
		ownexecfd = true;
	}

	if (pdrfork(procfdp, ctx->pdflags, RFEMBRYO) < 0) {
		*errp = errno;
		if (ownexecfd)
			(void)_close(execfd);
		return (SPAWN_PD_FAIL);
	}
	procfd = *procfdp;

	*errp = spawn_pd_configure(procfd, ctx);
	if (*errp == 0 && ctx->pid != NULL && pdgetpid(procfd, ctx->pid) != 0)
		*errp = errno;
	if (*errp != 0) {
		(void)_close(procfd);		/* destroys the embryo */
		if (ownexecfd)
			(void)_close(execfd);
		return (SPAWN_PD_FAIL);
	}

	/*
	 * Run it.  A path we opened ourselves is run by path (AT_FDCWD), so the
	 * kernel re-resolves it in the embryo and installs nothing -- a
	 * fork()+exec() child would not have a descriptor of its own executable
	 * either.  A descriptor the caller supplied is run as-is, with
	 * fexecve(2) semantics (AT_EMPTY_PATH).
	 */
	av = __DECONST(char **, argv);
	ev = __DECONST(char **, envp != NULL ? envp : environ);
	if (ownexecfd)
		rc = pdexec(procfd, AT_FDCWD, path, av, ev, 0);
	else
		rc = pdexec(procfd, execfd, "", av, ev, AT_EMPTY_PATH);
	if (rc == 0) {
		if (ownexecfd)
			(void)_close(execfd);
		return (SPAWN_PD_OK);
	}
	serrno = errno;
	(void)_close(procfd);			/* failed load destroyed it */
	if (ownexecfd)
		(void)_close(execfd);
	*errp = serrno;

	switch (serrno) {
	case ELOOP:
	case ENAMETOOLONG:
	case ENOENT:
	case ENOTDIR:
	case EACCES:
		/* A property of the path tried, not of the request. */
		return (SPAWN_PD_NEXT);
	default:
		return (SPAWN_PD_FAIL);
	}
}

/*
 * Re-run a file with no recognised format through the shell, as execvp(3)
 * does on ENOEXEC.  argv[0] is replaced by the path, so the shell sees the
 * script as its script argument.
 */
static enum spawn_pd_try
spawn_pd_shell(const struct spawn_pd_ctx *ctx, const char *path,
    char * const argv[], char * const envp[], int *procfdp, int *errp)
{
	const char **memp;
	enum spawn_pd_try r;
	size_t cnt;

	for (cnt = 0; argv[cnt] != NULL; ++cnt)
		;
	/*
	 * At least three entries, so that "sh", the path and the terminator
	 * fit even for an empty argv; otherwise cnt covers the terminator,
	 * since argv[0] is dropped.
	 */
	memp = malloc(MAX(3, cnt + 2) * sizeof(*memp));
	if (memp == NULL) {
		*errp = ENOMEM;
		return (SPAWN_PD_FAIL);
	}
	if (cnt > 0) {
		memp[0] = argv[0];
		memp[1] = path;
		memcpy(&memp[2], &argv[1], cnt * sizeof(*memp));
	} else {
		memp[0] = "sh";
		memp[1] = path;
		memp[2] = NULL;
	}
	r = spawn_pd_create(ctx, _PATH_BSHELL, -1,
	    __DECONST(char * const *, memp), envp, procfdp, errp);
	free(memp);
	/* Whatever happened, the ENOEXEC fallback is the end of the search. */
	return (r == SPAWN_PD_OK ? SPAWN_PD_OK : SPAWN_PD_FAIL);
}

/*
 * spawn_pd_create() plus execvp(3)'s ENOEXEC shell fallback.
 */
static enum spawn_pd_try
spawn_pd_prog(const struct spawn_pd_ctx *ctx, const char *path,
    char * const argv[], char * const envp[], int *procfdp, int *errp)
{
	enum spawn_pd_try r;

	r = spawn_pd_create(ctx, path, -1, argv, envp, procfdp, errp);
	if (r == SPAWN_PD_FAIL && *errp == ENOEXEC)
		return (spawn_pd_shell(ctx, path, argv, envp, procfdp, errp));
	return (r);
}

/*
 * The PATH walk of posix_spawnp(3), following execvp(3): a name containing a
 * slash is used as given, an empty name fails, and otherwise each PATH
 * component is tried in turn, an empty component meaning the current
 * directory.  If some candidate existed but could not be executed, that is
 * reported as EACCES rather than ENOENT.
 */
static enum spawn_pd_try
spawn_pd_progp(const struct spawn_pd_ctx *ctx, const char *name,
    char * const argv[], char * const envp[], int *procfdp, int *errp)
{
	char buf[MAXPATHLEN];
	const char *env_path, *np, *op, *p;
	size_t ln, lp;
	enum spawn_pd_try r;
	bool eacces;

	if (strchr(name, '/') != NULL)
		return (spawn_pd_prog(ctx, name, argv, envp, procfdp, errp));
	if (*name == '\0') {
		*errp = ENOENT;
		return (SPAWN_PD_FAIL);
	}
	if ((env_path = getenv("PATH")) == NULL)
		env_path = _PATH_DEFPATH;

	eacces = false;
	op = env_path;
	ln = strlen(name);
	while (op != NULL) {
		np = strchrnul(op, ':');
		if (np == op) {
			p = ".";
			lp = 1;
		} else {
			p = op;
			lp = np - op;
		}
		op = *np == '\0' ? NULL : np + 1;

		/*
		 * Skip a component that cannot yield a usable path.  Unlike
		 * execvp(3) there is no warning to write: posix_spawnp(3)
		 * reports through its return value, and nothing here runs in
		 * a context where stderr is the right channel.
		 */
		if (lp + ln + 2 > sizeof(buf))
			continue;

		memcpy(&buf[0], p, lp);
		buf[lp] = '/';
		memcpy(&buf[lp + 1], name, ln);
		buf[lp + ln + 1] = '\0';

		r = spawn_pd_prog(ctx, buf, argv, envp, procfdp, errp);
		if (r != SPAWN_PD_NEXT)
			return (r);
		if (*errp == EACCES)
			eacces = true;
	}
	*errp = eacces ? EACCES : ENOENT;
	return (SPAWN_PD_FAIL);
}

/*
 * Spawn through the embryonic-process interface.  Returns 0, or the error to
 * be reported.
 */
static int
do_posix_spawn(pid_t *pid, const char *path,
    const posix_spawn_file_actions_t *fa,
    const posix_spawnattr_t *sa,
    char * const argv[], char * const envp[], bool use_env_path)
{
	struct spawn_pd_ctx ctx;
	int error, execfd, procfd;
	enum spawn_pd_try r;

	execfd = sa != NULL ? (*sa)->sa_execfd : -1;

	ctx.fa = fa;
	ctx.sa = sa;
	ctx.pid = pid;
	if (sa != NULL && (*sa)->sa_pdrfork_fdp != NULL) {
		/*
		 * The caller takes the process descriptor and owns the child's
		 * lifetime from here, so honor exactly the flags it asked for.
		 */
		ctx.pdflags = PD_CLOEXEC | (*sa)->sa_pdflags;
	} else {
		/*
		 * We close the only descriptor below, so the child must not die
		 * with it: PD_DAEMON keeps it alive, and leaving PD_NOWAITPID
		 * clear keeps it reapable through waitpid(2) -- the fork()+exec()
		 * child semantics POSIX requires.
		 */
		ctx.pdflags = PD_CLOEXEC | PD_DAEMON;
	}

	/*
	 * POSIX_SPAWN_DISABLE_ASLR_NP is applied with procctl(P_PROCDESC), which
	 * requires CAP_PROCCTL on the descriptor; that right is withheld unless
	 * asked for, so request it exactly when it is needed.
	 */
	if (sa != NULL && ((*sa)->sa_flags & POSIX_SPAWN_DISABLE_ASLR_NP) != 0)
		ctx.pdflags |= PD_PROCCTL_CAP;

	/*
	 * A descriptor supplied through the attributes names the executable
	 * outright, so neither the PATH walk nor the ENOEXEC fallback
	 * applies to it.
	 */
	if (execfd != -1)
		r = spawn_pd_create(&ctx, NULL, execfd, argv, envp, &procfd,
		    &error);
	else if (use_env_path)
		r = spawn_pd_progp(&ctx, path, argv, envp, &procfd, &error);
	else
		r = spawn_pd_prog(&ctx, path, argv, envp, &procfd, &error);

	if (r != SPAWN_PD_OK)
		return (error);

	if (sa != NULL && (*sa)->sa_pdrfork_fdp != NULL)
		*((*sa)->sa_pdrfork_fdp) = procfd;
	else
		(void)_close(procfd);
	return (0);
}

int
posix_spawn(pid_t *pid, const char *path,
    const posix_spawn_file_actions_t *fa,
    const posix_spawnattr_t *sa,
    char * const argv[], char * const envp[])
{
	return (do_posix_spawn(pid, path, fa, sa, argv, envp, false));
}

int
posix_spawnp(pid_t *pid, const char *path,
    const posix_spawn_file_actions_t *fa,
    const posix_spawnattr_t *sa,
    char * const argv[], char * const envp[])
{
	return (do_posix_spawn(pid, path, fa, sa, argv, envp, true));
}

/*
 * File descriptor actions
 */

int
posix_spawn_file_actions_init(posix_spawn_file_actions_t *ret)
{
	posix_spawn_file_actions_t fa;

	fa = malloc(sizeof(struct __posix_spawn_file_actions));
	if (fa == NULL)
		return (errno);

	STAILQ_INIT(&fa->fa_list);
	*ret = fa;
	return (0);
}

int
posix_spawn_file_actions_destroy(posix_spawn_file_actions_t *fa)
{
	posix_spawn_file_actions_entry_t *fae;

	while ((fae = STAILQ_FIRST(&(*fa)->fa_list)) != NULL) {
		/* Remove file action entry from the queue */
		STAILQ_REMOVE_HEAD(&(*fa)->fa_list, fae_list);

		/* Deallocate file action entry */
		if (fae->fae_action == FAE_OPEN ||
		    fae->fae_action == FAE_CHDIR)
			free(fae->fae_path);
		free(fae);
	}

	free(*fa);
	return (0);
}

int
posix_spawn_file_actions_addopen(posix_spawn_file_actions_t * __restrict fa,
    int fildes, const char * __restrict path, int oflag, mode_t mode)
{
	posix_spawn_file_actions_entry_t *fae;
	int error;

	if (fildes < 0)
		return (EBADF);

	/* Allocate object */
	fae = malloc(sizeof(posix_spawn_file_actions_entry_t));
	if (fae == NULL)
		return (errno);

	/* Set values and store in queue */
	fae->fae_action = FAE_OPEN;
	fae->fae_path = strdup(path);
	if (fae->fae_path == NULL) {
		error = errno;
		free(fae);
		return (error);
	}
	fae->fae_fildes = fildes;
	fae->fae_oflag = oflag;
	fae->fae_mode = mode;

	STAILQ_INSERT_TAIL(&(*fa)->fa_list, fae, fae_list);
	return (0);
}

int
posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t *fa,
    int fildes, int newfildes)
{
	posix_spawn_file_actions_entry_t *fae;

	if (fildes < 0 || newfildes < 0)
		return (EBADF);

	/* Allocate object */
	fae = malloc(sizeof(posix_spawn_file_actions_entry_t));
	if (fae == NULL)
		return (errno);

	/* Set values and store in queue */
	fae->fae_action = FAE_DUP2;
	fae->fae_fildes = fildes;
	fae->fae_newfildes = newfildes;

	STAILQ_INSERT_TAIL(&(*fa)->fa_list, fae, fae_list);
	return (0);
}

int
posix_spawn_file_actions_addclose(posix_spawn_file_actions_t *fa,
    int fildes)
{
	posix_spawn_file_actions_entry_t *fae;

	if (fildes < 0)
		return (EBADF);

	/* Allocate object */
	fae = malloc(sizeof(posix_spawn_file_actions_entry_t));
	if (fae == NULL)
		return (errno);

	/* Set values and store in queue */
	fae->fae_action = FAE_CLOSE;
	fae->fae_fildes = fildes;

	STAILQ_INSERT_TAIL(&(*fa)->fa_list, fae, fae_list);
	return (0);
}

int
posix_spawn_file_actions_addchdir_np(posix_spawn_file_actions_t *
    __restrict fa, const char *__restrict path)
{
	posix_spawn_file_actions_entry_t *fae;
	int error;

	fae = malloc(sizeof(posix_spawn_file_actions_entry_t));
	if (fae == NULL)
		return (errno);

	fae->fae_action = FAE_CHDIR;
	fae->fae_path = strdup(path);
	if (fae->fae_path == NULL) {
		error = errno;
		free(fae);
		return (error);
	}

	STAILQ_INSERT_TAIL(&(*fa)->fa_list, fae, fae_list);
	return (0);
}
__weak_reference(posix_spawn_file_actions_addchdir_np,
    posix_spawn_file_actions_addchdir);

int
posix_spawn_file_actions_addfchdir_np(posix_spawn_file_actions_t *__restrict fa,
    int fildes)
{
	posix_spawn_file_actions_entry_t *fae;

	if (fildes < 0)
		return (EBADF);

	/* Allocate object */
	fae = malloc(sizeof(posix_spawn_file_actions_entry_t));
	if (fae == NULL)
		return (errno);

	fae->fae_action = FAE_FCHDIR;
	fae->fae_fildes = fildes;

	STAILQ_INSERT_TAIL(&(*fa)->fa_list, fae, fae_list);
	return (0);
}

__weak_reference(posix_spawn_file_actions_addfchdir_np,
    posix_spawn_file_actions_addfchdir);

int
posix_spawn_file_actions_addclosefrom_np (posix_spawn_file_actions_t *
    __restrict fa, int from)
{
	posix_spawn_file_actions_entry_t *fae;

	if (from < 0)
		return (EBADF);

	/* Allocate object */
	fae = malloc(sizeof(posix_spawn_file_actions_entry_t));
	if (fae == NULL)
		return (errno);

	fae->fae_action = FAE_CLOSEFROM;
	fae->fae_fildes = from;

	STAILQ_INSERT_TAIL(&(*fa)->fa_list, fae, fae_list);
	return (0);
}

/*
 * Spawn attributes
 */

int
posix_spawnattr_init(posix_spawnattr_t *ret)
{
	posix_spawnattr_t sa;

	sa = calloc(1, sizeof(struct __posix_spawnattr));
	if (sa == NULL)
		return (errno);
	sa->sa_execfd = -1;

	/* Set defaults as specified by POSIX, cleared above */
	*ret = sa;
	return (0);
}

int
posix_spawnattr_destroy(posix_spawnattr_t *sa)
{
	free(*sa);
	return (0);
}

int
posix_spawnattr_getflags(const posix_spawnattr_t * __restrict sa,
    short * __restrict flags)
{
	*flags = (*sa)->sa_flags;
	return (0);
}

int
posix_spawnattr_getpgroup(const posix_spawnattr_t * __restrict sa,
    pid_t * __restrict pgroup)
{
	*pgroup = (*sa)->sa_pgroup;
	return (0);
}

int
posix_spawnattr_getschedparam(const posix_spawnattr_t * __restrict sa,
    struct sched_param * __restrict schedparam)
{
	*schedparam = (*sa)->sa_schedparam;
	return (0);
}

int
posix_spawnattr_getschedpolicy(const posix_spawnattr_t * __restrict sa,
    int * __restrict schedpolicy)
{
	*schedpolicy = (*sa)->sa_schedpolicy;
	return (0);
}

int
posix_spawnattr_getsigdefault(const posix_spawnattr_t * __restrict sa,
    sigset_t * __restrict sigdefault)
{
	*sigdefault = (*sa)->sa_sigdefault;
	return (0);
}

int
posix_spawnattr_getsigmask(const posix_spawnattr_t * __restrict sa,
    sigset_t * __restrict sigmask)
{
	*sigmask = (*sa)->sa_sigmask;
	return (0);
}

int
posix_spawnattr_getexecfd_np(const posix_spawnattr_t * __restrict sa,
    int * __restrict fdp)
{
	*fdp = (*sa)->sa_execfd;
	return (0);
}

int
posix_spawnattr_getprocdescp_np(const posix_spawnattr_t * __restrict sa,
    int ** __restrict fdpp, int * __restrict pdrflagsp)
{
	*fdpp = (*sa)->sa_pdrfork_fdp;
	*pdrflagsp = (*sa)->sa_pdflags;
	return (0);
}

int
posix_spawnattr_setflags(posix_spawnattr_t *sa, short flags)
{
	if ((flags & ~(POSIX_SPAWN_RESETIDS | POSIX_SPAWN_SETPGROUP |
	    POSIX_SPAWN_SETSCHEDPARAM | POSIX_SPAWN_SETSCHEDULER |
	    POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK |
	    POSIX_SPAWN_DISABLE_ASLR_NP)) != 0)
		return (EINVAL);
	(*sa)->sa_flags = flags;
	return (0);
}

int
posix_spawnattr_setpgroup(posix_spawnattr_t *sa, pid_t pgroup)
{
	(*sa)->sa_pgroup = pgroup;
	return (0);
}

int
posix_spawnattr_setschedparam(posix_spawnattr_t * __restrict sa,
    const struct sched_param * __restrict schedparam)
{
	(*sa)->sa_schedparam = *schedparam;
	return (0);
}

int
posix_spawnattr_setschedpolicy(posix_spawnattr_t *sa, int schedpolicy)
{
	(*sa)->sa_schedpolicy = schedpolicy;
	return (0);
}

int
posix_spawnattr_setsigdefault(posix_spawnattr_t * __restrict sa,
    const sigset_t * __restrict sigdefault)
{
	(*sa)->sa_sigdefault = *sigdefault;
	return (0);
}

int
posix_spawnattr_setsigmask(posix_spawnattr_t * __restrict sa,
    const sigset_t * __restrict sigmask)
{
	(*sa)->sa_sigmask = *sigmask;
	return (0);
}

int
posix_spawnattr_setexecfd_np(posix_spawnattr_t * __restrict sa,
    int execfd)
{
	(*sa)->sa_execfd = execfd;
	return (0);
}

int
posix_spawnattr_setprocdescp_np(const posix_spawnattr_t * __restrict sa,
    int * __restrict fdp, int pdrflags)
{
	(*sa)->sa_pdrfork_fdp = fdp;
	(*sa)->sa_pdflags = pdrflags;
	return (0);
}
