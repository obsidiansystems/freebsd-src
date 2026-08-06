/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 John Ericson
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

/*
 * Embryonic process creation: pdrfork(RFEMBRYO), pdsetfd().
 *
 * pdrfork() with RFEMBRYO creates an unscheduled process with no address
 * space and no program, returning a process descriptor fd.  pdsetfd()
 * installs file descriptors into it.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/acct.h>
#include <sys/capsicum.h>
#include <sys/eventhandler.h>
#include <sys/exec.h>
#include <sys/fcntl.h>
#include <sys/filedesc.h>
#include <sys/imgact.h>
#include <sys/imgact_elf.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/procdesc.h>
#include <sys/ptrace.h>
#include <sys/racct.h>
#include <sys/resourcevar.h>
#include <sys/sched.h>
#include <sys/sdt.h>
#include <sys/signalvar.h>
#include <sys/stat.h>
#include <sys/sx.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/unistd.h>
#include <sys/vnode.h>

#include <security/audit/audit.h>
#include <security/mac/mac_framework.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/uma.h>

SDT_PROVIDER_DECLARE(proc);
SDT_PROBE_DECLARE(proc, , , create);
SDT_PROBE_DECLARE(proc, , , exec);
SDT_PROBE_DECLARE(proc, , , exec__failure);
SDT_PROBE_DECLARE(proc, , , exec__success);

/*
 * Resolve a process descriptor to its process, returning with the
 * process locked and holding a reference to the process-descriptor
 * file in *fpp.  The caller must fdrop(*fpp) once it is done with the
 * process.
 *
 * That held reference is what keeps the embryonic process alive after
 * the caller drops the process lock: without it, a concurrent close(2)
 * of the descriptor (e.g. from a sibling thread sharing the fd table)
 * could be the last reference, run proc_destroy_embryonic(), and free
 * the process out from under the caller.  On error *fpp is NULL.
 */
static int
procdesc_find(struct thread *td, int pdfd, const cap_rights_t *cap_rights,
    struct proc **pp, struct file **fpp)
{
	int error;

	sx_slock(&proctree_lock);
	error = fget_procdesc(td, pdfd, cap_rights, EINVAL, fpp, NULL, pp);
	sx_sunlock(&proctree_lock);
	return (error);
}

/*
 * kern_pdnew: allocate an embryonic process.
 *
 * The process is created with no address space and no image: a bare process
 * object with an empty descriptor table, default signal dispositions, and
 * nothing blocked.  It is in PRS_NEW with P_INEXEC set, and cannot be
 * started until pdexec() gives it something to run.
 *
 * Splitting allocation from image loading keeps the interface a builder --
 * allocate, configure, commit -- rather than having creation silently also
 * decide what the process will be.
 */
int
kern_pdnew(struct thread *td, int flags, int *fdp, pid_t *pidp)
{
	struct proc *p1, *p2;
	struct thread *td2;
	struct filedesc *newfd;
	struct pwddesc *newpd;
	struct sigacts *newsigacts;
	struct file *fp_procdesc;
	struct filecaps fcaps;
	int error, fd_num;

	p1 = td->td_proc;


	/*
	 * Allocate the process descriptor fd in the parent.
	 *
	 * As for pdfork(2), CAP_PTRACE is withheld unless the caller asks for
	 * it: a descriptor must be deliberately prepared for debugging before
	 * it confers that authority, which matters all the more here, where
	 * the descriptor is routinely handed to someone else to start.
	 */
	filecaps_fill(&fcaps);
	if ((flags & PD_PTRACE_CAP) == 0)
		cap_rights_clear(&fcaps.fc_rights, CAP_PTRACE);
	error = procdesc_falloc(td, &fp_procdesc, &fd_num, flags, &fcaps);
	if (error != 0) {
		filecaps_free(&fcaps);
		return (error);
	}

	error = fork_alloc_proc(td, 0, &p2, &td2);
	if (error != 0) {
		fdclose(td, fp_procdesc, fd_num);
		fdrop(fp_procdesc, td);
		return (error);
	}

	fork_register_proc(p2, td2, 0);

	/* Fresh file descriptors — empty table. */
	newpd = pdinit(p1->p_pd, false);
	newfd = fdinit();
	newsigacts = sigacts_alloc();

	bzero(&p2->p_startzero,
	    __rangeof(struct proc, p_startzero, p_endzero));
	/*
	 * Inherit the copied fields (e.g. p_reapsubtree, the reaper
	 * subtree this process belongs to) from the caller, as do_fork()
	 * does; fork_proc_tree() overrides p_reapsubtree for a reaper root.
	 */
	bcopy(&p1->p_startcopy, &p2->p_startcopy,
	    __rangeof(struct proc, p_startcopy, p_endcopy));

	PROC_LOCK(p2);

	bzero(&td2->td_startzero,
	    __rangeof(struct thread, td_startzero, td_endzero));
	/*
	 * Unlike do_fork(), do not bulk-copy the caller's td_startcopy
	 * range.  An embryo is not a copy of its creator, so inheritance
	 * here is opt-in: start from zero and take only what the new thread
	 * genuinely needs.
	 *
	 * Bulk-copying would be actively wrong, not merely impure.  That
	 * range holds userspace pointers -- the robust mutex list heads, the
	 * fast sigblock word, the extended error pointer -- which name
	 * addresses in the *caller's* address space.  The embryo gets a
	 * fresh vmspace from exec, where those addresses mean something
	 * else entirely; umtx_thread_cleanup() would later write
	 * OWNER_DIED bits through them into unrelated memory of the new
	 * program.  execve() zeroes them via umtx_exec() and
	 * sigfastblock_clear(), but neither can run here: umtx_exec()
	 * asserts p == curproc, and sigfastblock_clear() acts on curthread,
	 * which is the caller rather than td2.  Zeroing is the correct
	 * post-exec state (cf. thread_create(), kern_thr.c).
	 *
	 * td_sigmask is deliberately left empty rather than inherited: a
	 * process created this way blocks nothing until it says otherwise.
	 * (execve() preserves the mask, but there is no prior program here
	 * whose mask could be preserved.)
	 */
	bzero(&td2->td_startcopy,
	    __rangeof(struct thread, td_startcopy, td_endcopy));

	/*
	 * Scheduling parameters are the one thing inherited: sched_fork()
	 * below derives the child's priority from td_base_pri, so these
	 * must already be set when it runs.
	 */
	td2->td_rqindex = td->td_rqindex;
	td2->td_base_pri = td->td_base_pri;
	td2->td_priority = td->td_priority;
	td2->td_pri_class = td->td_pri_class;
	td2->td_user_pri = td->td_user_pri;
	td2->td_base_user_pri = td->td_base_user_pri;
	td2->td_flags = TDF_INMEM;
	td2->td_lend_user_pri = PRI_MAX;

	thread_lock(td);
	sched_fork(td, td2);
	thread_unlock(td);

	p2->p_flag = P_INMEM | P_INEXEC;
	p2->p_flag2 = 0;
	p2->p_swtick = ticks;

	p2->p_sigacts = newsigacts;
	p2->p_sigparent = SIGCHLD;

	p2->p_textvp = NULL;
	p2->p_textdvp = NULL;
	p2->p_binname = NULL;
	/*
	 * p_args is in the p_startcopy range, so the bcopy above left a
	 * borrowed reference to the caller's args.  Clear it: nothing reads
	 * an embryo's p_args before exec_finalize() installs an owned copy,
	 * and this keeps proc_destroy_embryonic()'s pargs_drop() correct on
	 * the failure path (NULL) as well as the success path (owned).
	 */
	p2->p_args = NULL;

	p2->p_fd = newfd;
	p2->p_fdtol = NULL;
	p2->p_pd = newpd;
	p2->p_vmspace = NULL;	/* pdexec(2) gives it one */

	/* lim_fork() requires both process locks; p_limit is copy-on-write. */
	PROC_LOCK(p1);
	lim_fork(p1, p2);
	thread_cow_get_proc(td2, p2);
	pstats_fork(p1->p_stats, p2->p_stats);
	PROC_UNLOCK(p1);

	p2->p_sysent = p1->p_sysent;

	PROC_UNLOCK(p2);

	/* Process group and parent attachment. */
	p2->p_peers = NULL;
	p2->p_leader = p2;

	sx_xlock(&proctree_lock);
	PGRP_LOCK(p1->p_pgrp);
	PROC_LOCK(p2);
	PROC_LOCK(p1);
	fork_proc_tree(p1, p2, false);

	/* Set up the process descriptor. */
	procdesc_new(p2, flags);

	/*
	 * Account for the references that will hold the zombie once the process
	 * exits, exactly as do_fork() does for an RFPROCDESC child: the
	 * descriptor always keeps one, and unless the caller opted out with
	 * PD_NOWAITPID the creating process keeps another so it can waitpid(2)
	 * the child -- the fork()+exec() semantics posix_spawn(3) relies on.
	 */
	p2->p_zombieref = PZOMBIEREF_PROCDESC;
	if ((flags & PD_NOWAITPID) == 0)
		p2->p_zombieref |= PZOMBIEREF_PARENT | PZOMBIEREF_NEEDPARENT;

	/*
	 * Do NOT announce the new process to fork observers here.  An embryo
	 * that is destroyed before pdstart() never runs, so process_fork and
	 * process_exit must never see it: an unbalanced fork leaks per-proc
	 * state in handlers that pair the two (filemon, hwpmc).  The
	 * process_fork event and the proc:::create probe are fired from
	 * pdstart() instead, once the process commits to running.
	 */

	/*
	 * Link the process descriptor to p2.  Our reference is held until
	 * construction finishes below: without it a concurrent close(2) of
	 * the descriptor (from a sibling thread that guessed fd_num) could be
	 * the last reference, run proc_destroy_embryonic(), and free p2 out
	 * from under us.
	 */
	procdesc_finit(p2->p_procdesc, fp_procdesc);

	racct_proc_fork_done(p2);
	/*
	 * The process is complete as far as it goes.  Drop our construction
	 * reference; the descriptor fd now keeps it alive.
	 */
	if (pidp != NULL)
		*pidp = p2->p_pid;
	fdrop(fp_procdesc, td);
	*fdp = fd_num;
	return (0);
}


int
sys_pdsetfd(struct thread *td, struct pdsetfd_args *uap)
{
	struct proc *p;
	struct file *fp, *fp_pd;
	struct filecaps fcaps;
	cap_rights_t rights;
	bool restricted;
	int error;

	/*
	 * pdsetfd() gets its own `CAP_*` unlike the other two syscalls
	 * in the non-fork-exec process spawning lifecycle (pdnew() and
	 * pdstart()). See the man pages for why.
	 */
	error = procdesc_find(td, uap->procfd,
	    cap_rights_init(&rights, CAP_PDSETFD), &p, &fp_pd);
	if (error != 0)
		return (error);

	/* Must be an embryonic (P_INEXEC, PRS_NEW) process. */
	if (p->p_state != PRS_NEW || (p->p_flag & P_INEXEC) == 0) {
		PROC_UNLOCK(p);
		fdrop(fp_pd, td);
		return (EINVAL);
	}
	/*
	 * Decide whether descriptor installation into this embryo is
	 * "restricted" (see the guard below).  Two independent triggers:
	 *
	 *   - The embryo's exec conferred a set-user-ID/set-group-ID
	 *     credential (P_SUGID) -- the same condition execve() uses to
	 *     drive fdsetugidsafety().
	 *
	 *   - The caller (the injector) is a different user or group than the
	 *     embryo's creator, so the embryo may carry authority the caller
	 *     lacks even without any set-id bit -- e.g. a root-created
	 *     procdesc delegated (via SCM_RIGHTS) to a weaker process.  This
	 *     half is skipped when the embryo itself runs in capability mode:
	 *     a sandboxed process draws its authority from its file
	 *     descriptors, not its ambient uid/gid, so the divergence is not
	 *     meaningful and CAP_PDSETFD plus the preserved filecaps govern
	 *     instead.  It is the embryo's capability mode that matters, not
	 *     the caller's: the check protects the embryo, so what counts is
	 *     whether the embryo's ambient identity confers real authority.
	 *
	 * The embryo has not run, so its credential reflects exactly
	 * pdnew()'s exec and cannot change under us before pdstart().
	 */
	restricted = (p->p_flag & P_SUGID) != 0 ||
	    ((p->p_ucred->cr_flags & CRED_FLAG_CAPMODE) == 0 &&
	    (td->td_ucred->cr_uid != p->p_ucred->cr_uid ||
	    td->td_ucred->cr_gid != p->p_ucred->cr_gid));
	PROC_UNLOCK(p);

	/*
	 * Look up the fd to install from the caller's fd table, capturing
	 * its capability rights so the installed descriptor carries exactly
	 * the same (possibly restricted) rights.  Using fget() + NULL fcaps
	 * would instead grant the child full rights (filecaps_fill()), a
	 * capability escape for a sandboxed caller.  This mirrors pddupfd().
	 */
	error = fget_cap(td, uap->localfd, cap_rights_init(&rights), NULL,
	    &fp, &fcaps);
	if (error != 0) {
		fdrop(fp_pd, td);
		return (error);
	}

	/*
	 * When installation is restricted (a set-id embryo, or a caller who
	 * does not share the embryo's user/group; see above), refuse to
	 * install an "unsafe" descriptor -- one whose backing vnode can change
	 * out from under the process after it starts, e.g. a procfs node -- at
	 * descriptors 0, 1 or 2, the same protection fdsetugidsafety() applies
	 * across an ordinary set-id execve().
	 *
	 * This policy targets exactly 0/1/2 because those fds carry implicit
	 * significance in the C library (stdin/stdout/stderr): a privileged
	 * program may write to them via stdio without ever naming them, so a
	 * hostile descriptor there is a confused-deputy write primitive.
	 * Descriptors >= 3 have no such implicit meaning and FreeBSD already
	 * permits unsafe ones across execve().  That choice is a property of
	 * libc's runtime contract, independent of how the process was spawned
	 * (fork+exec closes or keeps fds uniformly too), so pdnew() simply
	 * honors FreeBSD's existing policy rather than inventing its own.
	 */
	if (restricted && uap->remotefd >= 0 && uap->remotefd <= 2 &&
	    fdesc_is_unsafe(fp)) {
		filecaps_free(&fcaps);
		fdrop(fp, td);
		fdrop(fp_pd, td);
		return (EPERM);
	}

	/*
	 * Install into the embryonic process's fd table at the
	 * caller-chosen descriptor number.  finstall_at() takes its own
	 * reference, so drop ours afterward regardless of outcome; on
	 * success it moves fcaps into the new descriptor, so only free them
	 * on failure.  The fp_pd reference held across this call keeps the
	 * process and its fd table alive against a concurrent close(2).
	 */
	error = finstall_at(td, p, fp, uap->remotefd, 0, &fcaps);
	if (error != 0)
		filecaps_free(&fcaps);
	fdrop(fp, td);
	fdrop(fp_pd, td);
	return (error);
}

/*
 * Argument block handed from pdexec(2) to the trampoline that runs in the
 * embryo.  It is freed by whichever side finishes with it: normally the
 * trampoline, via kern_execve().
 */
struct pdexec_args_blk {
	struct image_args	args;
	int			execfd;
};

/*
 * The trampoline.
 *
 * This runs as the embryonic process's own thread, on its first and only
 * trip out of the kernel, and simply execs.  Everything execve(2) does then
 * happens in the right context: the image is activated into curproc's
 * vmspace, the argument strings are copied out with a plain copyout(9),
 * umtx_exec() and sigfastblock_clear() act on curthread, and the descriptor
 * table is processed by fdcloseexec() as usual.  None of that has to be
 * taught about acting on another process.
 *
 * On success kern_execve() does not come back here; the thread returns to
 * userspace running the new program.  On failure there is nothing to return
 * to, since this process has never had a program, so it exits.
 */
static void
pdexec_trampoline(void *arg)
{
	struct pdexec_args_blk *blk = arg;
	struct thread *td = curthread;
	int error;

	error = kern_execve(td, &blk->args, NULL, NULL);
	free(blk, M_TEMP);

	/*
	 * EJUSTRETURN is how a successful execve(2) reports that the register
	 * state has been replaced and must not be touched again; returning
	 * from here does exactly that, and the process starts running its new
	 * program.
	 */
	if (error == EJUSTRETURN)
		return;

	/*
	 * The image could not be loaded.  A process that has never run has
	 * nothing to fall back to, so it dies here; its creator learns of it
	 * through the process descriptor.
	 */
	exit1(td, 0, SIGABRT);
	/* NOTREACHED */
}

/*
 * Release an embryonic process: mark it complete, announce it, and let it
 * run.
 *
 * Called with the process locked; returns it unlocked and scheduled.
 */
static void
pdstart_proc(struct proc *p)
{
	struct thread *td2;
	struct proc *pp;

	PROC_LOCK_ASSERT(p, MA_OWNED);

	/*
	 * Clear P_INEXEC and transition to normal state.  Wake any
	 * P_INEXEC_WAIT waiter (e.g. a racing pddupfd() parked in
	 * execve_block_wait()), as do_execve() does when it clears the
	 * flag; otherwise the waiter sleeps forever.
	 */
	MPASS(p->p_execblock == 0);
	if ((p->p_flag & P_INEXEC_WAIT) != 0)
		wakeup(&p->p_execblock);
	p->p_flag &= ~(P_INEXEC | P_INEXEC_WAIT);

	PROC_SLOCK(p);
	p->p_state = PRS_NORMAL;
	PROC_SUNLOCK(p);

	microuptime(&p->p_stats->p_start);

	PROC_UNLOCK(p);

	/*
	 * Announce the process to fork observers now that it has committed
	 * to running -- deferred from creation so that an embryo destroyed
	 * before it ever ran is never seen, which would leave process_fork
	 * unbalanced in handlers that pair it with process_exit (filemon,
	 * hwpmc).  Fire with no process lock held, as do_fork() does, and
	 * before the thread is scheduled so handlers are registered before
	 * it can run.  Inherit from the embryo's parent -- its creator, or
	 * the reaper if that has since exited -- not the possibly different
	 * caller; PHOLD keeps it alive across the call.
	 */
	sx_slock(&proctree_lock);
	pp = p->p_pptr;
	PHOLD(pp);
	sx_sunlock(&proctree_lock);
	EVENTHANDLER_DIRECT_INVOKE(process_fork, pp, p, RFPROC);
	SDT_PROBE3(proc, , , create, p, pp, RFPROC);
	PRELE(pp);

	/* Schedule the process's thread. */
	td2 = FIRST_THREAD_IN_PROC(p);
	thread_lock(td2);
	TD_SET_CAN_RUN(td2);
	sched_add(td2, SRQ_BORING);
}

/*
 * kern_pdexec: give an embryonic process a program, and run it.
 *
 * The exec itself is not performed here.  It is performed by the target, on
 * its own thread, in its own address space -- see pdexec_trampoline().  All
 * this call does is prepare the handoff and let the process go.
 *
 * The executable is named by a descriptor of the *caller*, but the exec runs
 * in the target, which has its own (empty) descriptor table.  So the
 * descriptor is installed into the target first, close-on-exec, at the same
 * number: the exec that follows both uses it and closes it, and a shebang
 * interpreter can still reach the script through /dev/fd/N while it lasts.
 */
static int
kern_pdexec(struct thread *td, int procfd, int execfd, struct image_args *args)
{
	struct pdexec_args_blk *blk;
	struct filecaps fcaps;
	struct proc *p2;
	struct thread *td2;
	struct file *fp_pd, *efp;
	cap_rights_t rights;
	int error;

	/*
	 * Deciding what a process will run is at least as much authority as
	 * configuring it, and releasing it is what pdkill(2) guards, so
	 * require both rights.
	 */
	cap_rights_init(&rights, CAP_PDSETFD);
	cap_rights_set(&rights, CAP_PDKILL);
	error = procdesc_find(td, procfd, &rights, &p2, &fp_pd);
	if (error != 0)
		return (error);

	/* Must be an embryo that has not been given a program yet. */
	if (p2->p_state != PRS_NEW || (p2->p_flag & P_INEXEC) == 0 ||
	    p2->p_textvp != NULL) {
		PROC_UNLOCK(p2);
		fdrop(fp_pd, td);
		return (EINVAL);
	}
	PROC_UNLOCK(p2);
	td2 = FIRST_THREAD_IN_PROC(p2);

	/*
	 * Hand the executable to the target, preserving the rights the
	 * caller retained on it rather than granting the child full rights.
	 */
	error = fget_cap(td, execfd, &cap_fexecve_rights, NULL, &efp, &fcaps);
	if (error != 0) {
		fdrop(fp_pd, td);
		return (error);
	}
	error = finstall_at(td, p2, efp, execfd, O_CLOEXEC, &fcaps);
	if (error != 0)
		filecaps_free(&fcaps);
	fdrop(efp, td);
	if (error != 0) {
		fdrop(fp_pd, td);
		return (error);
	}

	/*
	 * Give the process an empty address space, and build its kernel
	 * stack and trampoline.
	 *
	 * Both happen here rather than at creation so that an embryo which
	 * has not been given a program has no address space at all: there is
	 * nothing to describe until there is something to run.  The vmspace
	 * comes first because cpu_fork() needs a pmap to preload from on some
	 * architectures; the exec that follows replaces it, exactly as
	 * execve(2) replaces the address space of any other process.
	 */
	p2->p_vmspace = vmspace_alloc(p2->p_sysent->sv_minuser,
	    p2->p_sysent->sv_maxuser, pmap_pinit);
	if (p2->p_vmspace == NULL) {
		fdrop(fp_pd, td);
		return (ENOMEM);
	}
	cpu_fork(td, p2, td2, RFPROC);

	blk = malloc(sizeof(*blk), M_TEMP, M_WAITOK);
	blk->args = *args;
	blk->execfd = execfd;
	blk->args.fd = execfd;

	cpu_fork_kthread_handler(td2, pdexec_trampoline, blk);

	/*
	 * Release the process.  From here the target runs the trampoline and
	 * execs itself; there is nothing further for this call to do, and the
	 * result of the exec is reported through the process descriptor
	 * rather than through this syscall.
	 */
	PROC_LOCK(p2);
	pdstart_proc(p2);
	fdrop(fp_pd, td);
	return (0);
}

int
sys_pdexec(struct thread *td, struct pdexec_args *uap)
{
	struct image_args args;
	int error;

	if (uap->flags != 0)
		return (EINVAL);

	error = exec_copyin_args(&args, NULL, uap->argv, uap->envv);
	if (error != 0)
		return (error);

	error = kern_pdexec(td, uap->procfd, uap->fd, &args);
	if (error != 0) {
		exec_free_args(&args);
		return (error);
	}

	td->td_retval[0] = 0;
	return (0);
}
