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
 * Reset an embryonic process's effective ids to its real ids.
 *
 * This is seteuid(getuid()) and setegid(getgid()) applied to a process that
 * cannot run them itself.  It has to happen before pdexec(2), because the
 * access check for the image is made against the credential in force at the
 * time: dropping privilege afterwards would let a caller run a file that the
 * dropped-to identity could not, which is the opposite of what the request
 * means.  Nothing runs in an embryo between the two calls, so ordering them
 * is enough; it does not have to be a mode of the exec itself.
 *
 * No privilege check is needed.  The target is always the process's own real
 * ids, which seteuid(2) and setegid(2) permit unconditionally.
 */
static int
pdresetids_proc(struct proc *p2)
{
	struct ucred *newcred, *oldcred;
	struct uidinfo *euip;
	uid_t ruid;
	gid_t rgid;
	int error;

	/*
	 * The embryo is not running and no one else holds it, so its
	 * credential is stable and can be read before taking the lock --
	 * which uifind() requires, as it may sleep.
	 */
	ruid = p2->p_ucred->cr_ruid;
	rgid = p2->p_ucred->cr_rgid;

	newcred = crget();
	euip = uifind(ruid);
	PROC_LOCK(p2);
	oldcred = crcopysafe(p2, newcred);

#ifdef MAC
	error = mac_cred_check_seteuid(oldcred, ruid);
	if (error == 0)
		error = mac_cred_check_setegid(oldcred, rgid);
	if (error != 0) {
		PROC_UNLOCK(p2);
		uifree(euip);
		crfree(newcred);
		return (error);
	}
#else
	error = 0;
#endif

	if (oldcred->cr_uid != ruid) {
		change_euid(newcred, euip);
		setsugid(p2);
	}
	if (oldcred->cr_gid != rgid) {
		change_egid(newcred, rgid);
		setsugid(p2);
	}
	proc_set_cred(p2, newcred);
	PROC_UNLOCK(p2);
	uifree(euip);
	crfree(oldcred);
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
 * kern_pdexec: give an embryonic process its address space, by loading an
 * executable into it.
 *
 * This is the step pdnew() deliberately does not take: it decides what the
 * process will run.  pdstart() then releases it.
 *
 * On failure before the point of no return the embryo is untouched and the
 * caller may try again with a different executable, which is what a PATH
 * search wants.  Past that point (imgp.vmspace_destroyed) there is nothing
 * to retry with, but p_textvp is still NULL, so pdstart() refuses the
 * process and closing the descriptor destroys it.
 */
static int
kern_pdexec(struct thread *td, int procfd, int exec_fd,
    struct image_args *args, int flags)
{
	struct proc *p2;
	struct thread *td2;
	struct file *fp_pd;
	struct nameidata nd;
	struct ucred *oldcred;
	struct uidinfo *euip = NULL;
	uintptr_t stack_base;
	struct image_params image_params, *imgp;
	struct vattr attr;
	struct pargs *newargs = NULL;
	struct vnode *newtextvp;
	struct vnode *newtextdvp;
	cap_rights_t rights;
	char *newbinname;
#ifdef MAC
	struct label *interpvplabel = NULL;
	bool will_transition;
#endif
	int error;

	/*
	 * Loading the image needs the same authority as any other change to
	 * the embryo; releasing it needs what pdstart(2) needs, so ask for
	 * both when this call will also start the process.
	 */
	cap_rights_init(&rights, CAP_PDSETFD);
	if ((flags & PD_NOSTART) == 0)
		cap_rights_set(&rights, CAP_PDKILL);
	error = procdesc_find(td, procfd, &rights, &p2, &fp_pd);
	if (error != 0)
		return (error);

	/*
	 * Must be an embryo that has not been given an image yet.  p_textvp
	 * is what pdstart() keys on, so it doubles as the "already loaded"
	 * test here.
	 */
	if (p2->p_state != PRS_NEW || (p2->p_flag & P_INEXEC) == 0 ||
	    p2->p_textvp != NULL) {
		PROC_UNLOCK(p2);
		fdrop(fp_pd, td);
		return (EINVAL);
	}
	PROC_UNLOCK(p2);
	td2 = FIRST_THREAD_IN_PROC(p2);

	/*
	 * Validate the executable.  Nothing is committed until exec_activate()
	 * below replaces the address space, so a bad executable costs nothing.
	 */

	imgp = &image_params;
	newtextvp = NULL;
	newtextdvp = NULL;
	newbinname = NULL;

	bzero(imgp, sizeof(*imgp));
	imgp->attr = &attr;
	imgp->args = args;
	imgp->caller_td = td;

	args->fd = exec_fd;

#ifdef MAC
	error = mac_execve_enter(imgp, NULL);
	if (error)
		goto exec_fail;
#endif

	SDT_PROBE1(proc, , , exec, args->fname);

	/* Look up the executable from the caller's fd table. */
	error = exec_fgetvp(imgp, td, args->fd, &newtextvp);
	if (error != 0)
		goto exec_fail;

	/* Check permissions and map the first page. */
	error = exec_prepare_image(imgp);
	if (error)
		goto exec_fail_dealloc;

	/*
	 * Load the executable into the embryonic process.
	 *
	 * The image is already mapped (above).  Now wire it
	 * up to the process and run the image activators to create
	 * the vmspace.
	 */

	imgp->proc = p2;
	imgp->td = td2;

	oldcred = p2->p_ucred;

	p2->p_osrel = 0;
	p2->p_fctl0 = 0;
	p2->p_elf_brandinfo = NULL;

interpret:
	error = exec_activate(imgp, oldcred, &attr, &euip, NULL
#ifdef MAC
	    , interpvplabel, &will_transition
#endif
	    );
	if (error)
		goto exec_fail_dealloc;

	/*
	 * Special interpreter operation, cleanup and loop up to try to
	 * activate the interpreter.
	 */
	if (imgp->interpreted) {
		exec_interpreter_cleanup(imgp, td
#ifdef MAC
		    , &interpvplabel
#endif
		    );
		newtextvp = NULL;
		/*
		 * Free the previous iteration's namei resources before
		 * resolving the next interpreter (relevant for a multi-level
		 * chain, e.g. binmisc -> shebang), as do_execve() does.
		 * args->fname is non-NULL only after the namei path populated
		 * nd/newtextdvp/newbinname.
		 */
		if (args->fname != NULL) {
			if (newtextdvp != NULL) {
				vrele(newtextdvp);
				newtextdvp = NULL;
			}
			NDFREE_PNBUF(&nd);
			free(newbinname, M_PARGS);
			newbinname = NULL;
		}
		/* Resolve the interpreter. */
		if (imgp->interpreter_vp) {
			args->fname = NULL;
			exec_interpreter_vp(imgp, &newtextvp);
		} else {
			struct file *efp;
			struct filecaps efcaps;

			/*
			 * A shebang interpreter references the script as
			 * "/dev/fd/N" (N == exec_fd) in the rewritten
			 * arguments and must be able to open it.  Unlike
			 * fexecve(2), the embryonic process has a fresh
			 * descriptor table, so install the exec fd into it
			 * at that number, preserving its capability rights
			 * (fget_cap) rather than granting the child full
			 * rights on the executable.
			 */
			error = fget_cap(td, exec_fd, &cap_no_rights, NULL,
			    &efp, &efcaps);
			if (error != 0)
				goto exec_fail;
			error = finstall_at(td, p2, efp, exec_fd, 0,
			    &efcaps);
			if (error != 0)
				filecaps_free(&efcaps);
			fdrop(efp, td);
			if (error != 0)
				goto exec_fail;

			args->fname = imgp->interpreter_name;
			error = exec_interpreter_namei(imgp, td, &nd,
			    &newtextvp, &newtextdvp, &newbinname);
			if (error)
				goto exec_fail;
		}
		error = exec_prepare_image(imgp);
		if (error)
			goto exec_fail_dealloc;
		goto interpret;
	}

	error = exec_copyout_stack(imgp, &stack_base);
	if (error != 0)
		goto exec_fail_dealloc;

	/*
	 * Set up td2's kernel stack, PCB, and fork_trampoline via cpu_fork.
	 * This must run after the image activator has created p2's vmspace
	 * (exec_new_vmspace(), above): on i386/arm cpu_fork() dereferences
	 * vmspace_pmap(p2->p_vmspace) to preload pcb_cr3, which would panic
	 * while p2->p_vmspace is still NULL.  (amd64/arm64 do not touch
	 * p_vmspace here.)  Unlike do_fork(), where vm_forkproc() builds the
	 * vmspace before cpu_fork(), pdnew() gets its vmspace from exec, so
	 * cpu_fork() necessarily runs here in the exec path.  cpu_fork()
	 * copies the parent's trapframe/PCB, which is wasted work since
	 * sv_setregs (in exec_finalize below) overwrites the user registers.
	 *
	 * TODO: an embryonic cpu_fork() variant that only builds the
	 * trampoline would avoid both the ordering constraint and the waste.
	 */
	cpu_fork(td, p2, td2, RFPROC);

	newargs = exec_cache_args(imgp->args);

	vn_lock(imgp->vp, LK_SHARED | LK_RETRY);

	PROC_LOCK(p2);

	exec_set_comm(imgp, NULL, 0);

	exec_install_setid(imgp, td, oldcred);
#ifdef MAC
	if (imgp->credential_setid && will_transition)
		mac_vnode_execve_transition(oldcred, imgp->newcred, imgp->vp,
		    interpvplabel, imgp);
#endif

	/*
	 * Install the new credentials.  Unlike do_execve(), the embryonic
	 * process starts from a clean descriptor table, so there is no
	 * fdsetugidsafety()/fdcheckstd() pass to run beforehand.
	 */
	if (imgp->newcred != NULL) {
		proc_set_cred(p2, imgp->newcred);
		crfree(oldcred);
		oldcred = NULL;
	}

	exec_finalize(imgp, newtextvp, &newbinname, &newargs, stack_base);

	/*
	 * Cleanup -- runs on both success and failure paths.
	 */
exec_fail_dealloc:
	exec_cleanup_imgp(imgp, td, error);

	/* Clean up namei resources from interpreter resolution. */
	if (imgp->vp != NULL) {
		if (args->fname != NULL)
			NDFREE_PNBUF(&nd);
		if (newtextdvp != NULL)
			vrele(newtextdvp);
		free(newbinname, M_PARGS);
	}

	if (error != 0) {
exec_fail:
		SDT_PROBE1(proc, , , exec__failure, error);
	}

	exec_cleanup_cred(imgp, oldcred,
#ifdef MAC
	    interpvplabel,
#endif
	    args, newargs, euip);

	/*
	 * Unless the caller asked to keep the process stopped, release it
	 * here, so that loading a program and running it is one call -- what
	 * execve(2) does, aimed at another process.  PD_NOSTART instead
	 * leaves it for pdstart(2), so it can be configured with the image
	 * in place first.
	 */
	if (error == 0 && (flags & PD_NOSTART) == 0) {
		PROC_LOCK(p2);
		pdstart_proc(p2);
	}

	/*
	 * The process belongs to the caller either way: on success it now
	 * has an image, and is running unless PD_NOSTART was given; on
	 * failure it is left as it was, or -- past the point of no return --
	 * unstartable.  Destroying it is the caller's business, done by
	 * closing the descriptor.
	 */
	fdrop(fp_pd, td);
	return (error);
}

int
sys_pdexec(struct thread *td, struct pdexec_args *uap)
{
	struct image_args args;
	int error;

	if ((uap->flags & ~PD_ALLOWED_AT_EXEC) != 0)
		return (EINVAL);

	error = exec_copyin_args(&args, NULL, uap->argv, uap->envv);
	if (error != 0)
		return (error);

	error = kern_pdexec(td, uap->procfd, uap->fd, &args, uap->flags);
	if (error != 0) {
		exec_free_args(&args);
		return (error);
	}

	td->td_retval[0] = 0;
	return (0);
}

/*
 * Install a range of the caller's descriptors into an embryonic process at
 * the same descriptor numbers: the bulk form of pdsetfd(2).
 *
 * fork(2)/execve(2) forces an inherit-everything-then-close model, where the
 * child begins with a copy of the whole table and the unwanted entries are
 * closed afterwards.  Here inheritance is opt-in: the caller names the range
 * it wants, and nothing else appears.  Consequently an embryo's descriptor
 * table only ever grows, and there is no operation to remove an entry from
 * another process's table.
 *
 * Descriptors marked close-on-exec are skipped, so what is copied is what
 * would have survived an execve(2); callers emulating those semantics need
 * not filter the range themselves.  Unused descriptors within the range are
 * skipped rather than being an error, since a range is a convenience for the
 * caller and not an assertion about which descriptors it holds.
 *
 * Capability rights are preserved per descriptor, as pdsetfd(2) does.
 */
int
sys_pdsetfdrange(struct thread *td, struct pdsetfdrange_args *uap)
{
	struct filedesc *fdp;
	struct proc *p;
	struct file *fp, *fp_pd;
	struct filecaps fcaps;
	cap_rights_t rights;
	uint8_t fdflags;
	u_int fd, highfd;
	bool restricted;
	int error, lastfile;

	if (uap->flags != 0)
		return (EINVAL);
	if (uap->highfd < uap->lowfd)
		return (EINVAL);

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
	restricted = (p->p_flag & P_SUGID) != 0 ||
	    ((p->p_ucred->cr_flags & CRED_FLAG_CAPMODE) == 0 &&
	    (td->td_ucred->cr_uid != p->p_ucred->cr_uid ||
	    td->td_ucred->cr_gid != p->p_ucred->cr_gid));
	PROC_UNLOCK(p);

	/*
	 * Clamp to the caller's highest open descriptor so that the common
	 * "copy everything from here up" idiom does not walk to UINT_MAX.
	 */
	fdp = td->td_proc->p_fd;
	FILEDESC_SLOCK(fdp);
	lastfile = fdlastfile(fdp);
	FILEDESC_SUNLOCK(fdp);
	if (lastfile < 0) {
		fdrop(fp_pd, td);
		return (0);
	}
	highfd = MIN(uap->highfd, (u_int)lastfile);

	for (fd = uap->lowfd; fd <= highfd; fd++) {
		error = fget_cap(td, fd, &cap_no_rights, &fdflags, &fp,
		    &fcaps);
		if (error != 0) {
			/* Not open: a gap in the range, not a failure. */
			error = 0;
			continue;
		}
		/*
		 * Skip descriptors a fork()+exec() child would not inherit:
		 * close-on-fork ones never survive the fork, and close-on-exec
		 * ones are dropped by the pdexec(2) that follows.  (A file action
		 * that dup2s such a descriptor is realised separately, through
		 * pdsetfd(2), so it is unaffected by this.)
		 */
		if ((fdflags & (UF_EXCLOSE | UF_FOCLOSE)) != 0) {
			fdrop(fp, td);
			filecaps_free(&fcaps);
			continue;
		}
		/* See sys_pdsetfd(): same restriction on descriptors 0-2. */
		if (restricted && fd <= 2 && fdesc_is_unsafe(fp)) {
			fdrop(fp, td);
			filecaps_free(&fcaps);
			error = EPERM;
			break;
		}
		error = finstall_at(td, p, fp, fd, 0, &fcaps);
		fdrop(fp, td);
		if (error != 0) {
			filecaps_free(&fcaps);
			break;
		}
	}

	fdrop(fp_pd, td);
	return (error);
}

/*
 * Configuring an embryonic process.
 *
 * pdnew(2) deliberately gives the new process a clean slate: an empty
 * descriptor table, default signal dispositions, nothing blocked.  Anything
 * a caller wants beyond that it must ask for, which is what these calls are
 * for.  They exist because the state in question belongs to a process that
 * cannot run code of its own, so the usual self-directed syscalls
 * (sigprocmask(2), sigaction(2), fchdir(2)) have nothing to run in.
 *
 * A caller emulating fork(2)/execve(2) inheritance -- posix_spawn(3), say --
 * uses these to reconstruct explicitly whatever that model would have
 * conferred implicitly.
 *
 * All of them require CAP_PDSETFD and, like pdsetfd(2), only apply to a
 * process that has not been started yet.
 */

/*
 * Resolve a procdesc to an embryo, checking it is still unstarted.  On
 * success the process is returned unlocked with *fpp holding a reference the
 * caller must fdrop(); *restrictedp reports whether descriptor installation
 * into it would be restricted (see sys_pdsetfd()).
 */
static int
pdconf_find(struct thread *td, int pdfd, struct proc **pp, struct file **fpp)
{
	cap_rights_t rights;
	struct proc *p;
	int error;

	error = procdesc_find(td, pdfd, cap_rights_init(&rights, CAP_PDSETFD),
	    &p, fpp);
	if (error != 0)
		return (error);
	if (p->p_state != PRS_NEW || (p->p_flag & P_INEXEC) == 0) {
		PROC_UNLOCK(p);
		fdrop(*fpp, td);
		*fpp = NULL;
		return (EINVAL);
	}
	*pp = p;
	return (0);
}

/*
 * Set the signal mask of an embryonic process.
 *
 * A process created by pdnew(2) blocks nothing, so a caller wanting the
 * fork(2) behaviour of inheriting its own mask must say so.  SIGKILL and
 * SIGSTOP cannot be blocked, as for sigprocmask(2).
 */
int
sys_pdsetsigmask(struct thread *td, struct pdsetsigmask_args *uap)
{
	struct proc *p;
	struct file *fp_pd;
	struct thread *td2;
	sigset_t mask;
	int error;

	error = copyin(uap->mask, &mask, sizeof(mask));
	if (error != 0)
		return (error);
	SIG_CANTMASK(mask);

	error = pdconf_find(td, uap->procfd, &p, &fp_pd);
	if (error != 0)
		return (error);

	/*
	 * The embryo is single-threaded and not running, so its mask can be
	 * assigned directly; there is no signal delivery to reconsider.
	 */
	td2 = FIRST_THREAD_IN_PROC(p);
	td2->td_sigmask = mask;
	PROC_UNLOCK(p);
	fdrop(fp_pd, td);
	return (0);
}

/*
 * Set signals to SIG_IGN in an embryonic process.
 *
 * execve(2) leaves ignored signals ignored while resetting caught ones to
 * their default; pdnew(2) has no prior program to inherit dispositions from,
 * so everything starts at SIG_DFL.  This restores the ignored ones.  Signals
 * absent from the set keep their default disposition; SIGKILL and SIGSTOP are
 * silently skipped, as they cannot be ignored.
 */
int
sys_pdsetsigign(struct thread *td, struct pdsetsigign_args *uap)
{
	struct proc *p;
	struct file *fp_pd;
	struct sigacts *ps;
	sigset_t ign;
	int error, sig;

	error = copyin(uap->ign, &ign, sizeof(ign));
	if (error != 0)
		return (error);

	error = pdconf_find(td, uap->procfd, &p, &fp_pd);
	if (error != 0)
		return (error);

	ps = p->p_sigacts;
	mtx_lock(&ps->ps_mtx);
	for (sig = 1; sig <= _SIG_MAXSIG; sig++) {
		if (!SIGISMEMBER(ign, sig))
			continue;
		if (sig == SIGKILL || sig == SIGSTOP)
			continue;
		ps->ps_sigact[_SIG_IDX(sig)] = SIG_IGN;
		/*
		 * Mirror the bookkeeping kern_sigaction() does for SIG_IGN:
		 * SIGCONT stays out of ps_sigignore so that it can still
		 * restart the process.
		 */
		if (sig != SIGCONT)
			SIGADDSET(ps->ps_sigignore, sig);
		SIGDELSET(ps->ps_sigcatch, sig);
		if (sig == SIGCHLD)
			ps->ps_flag |= PS_CLDSIGIGN;
	}
	mtx_unlock(&ps->ps_mtx);
	PROC_UNLOCK(p);
	fdrop(fp_pd, td);
	return (0);
}

/*
 * Set the working directory of an embryonic process to the directory named
 * by a descriptor of the caller.
 *
 * The lookup and the permission check are the caller's, exactly as they
 * would be for fchdir(2): a caller can only place the new process somewhere
 * it could itself have moved to.
 */
int
sys_pdchdir(struct thread *td, struct pdchdir_args *uap)
{
	struct proc *p;
	struct file *fp_pd, *fp;
	struct vnode *vp, *tdp;
	struct mount *mp;
	uint8_t fdflags;
	int error;

	error = getvnode_path(td, uap->dirfd, &cap_fchdir_rights, &fdflags,
	    &fp);
	if (error != 0)
		return (error);
	if ((fdflags & UF_RESOLVE_BENEATH) != 0) {
		fdrop(fp, td);
		return (ENOTCAPABLE);
	}
	vp = fp->f_vnode;
	vrefact(vp);
	fdrop(fp, td);

	vn_lock(vp, LK_SHARED | LK_RETRY);
	AUDIT_ARG_VNODE1(vp);
	error = change_dir(vp, td);
	/* Cross into whatever is mounted here, as fchdir(2) does. */
	while (error == 0 && (mp = vp->v_mountedhere) != NULL) {
		if (vfs_busy(mp, 0))
			continue;
		error = VFS_ROOT(mp, LK_SHARED, &tdp);
		vfs_unbusy(mp);
		if (error != 0)
			break;
		vput(vp);
		vp = tdp;
	}
	if (error != 0) {
		vput(vp);
		return (error);
	}
	VOP_UNLOCK(vp);

	error = pdconf_find(td, uap->procfd, &p, &fp_pd);
	if (error != 0) {
		vrele(vp);
		return (error);
	}
	PROC_UNLOCK(p);
	/* Consumes the reference taken above. */
	pwd_chdir_proc(p, vp);
	fdrop(fp_pd, td);
	return (0);
}

/*
 * Set the process group of an embryonic process.
 *
 * This is setpgid(2) aimed at a process that cannot call it for itself, and
 * it applies the same rules: the target may not be a session leader, a
 * pgid of zero means the target's own pid, joining an existing group
 * requires that group to be in the caller's session, and creating one is
 * only allowed under the target's own pid.
 *
 * It differs from setpgid(2) in dropping the P_EXEC check.  That check stops
 * a parent from moving a child that has already replaced its image, on the
 * grounds that the child is now a different program which may have made its
 * own arrangements.  An embryo has loaded an image but has never run an
 * instruction of it, so there are no arrangements to disturb; the creator is
 * still the only party that has ever acted on the process.  Without this,
 * POSIX_SPAWN_SETPGROUP would be unimplementable here, since pdnew(2) loads
 * the image up front and so sets P_EXEC before the caller can ask.
 */
int
sys_pdsetpgid(struct thread *td, struct pdsetpgid_args *uap)
{
	struct proc *curp = td->td_proc;
	struct proc *p;
	struct file *fp_pd;
	struct pgrp *newpgrp;
	pid_t pgid;
	int error;

	pgid = uap->pgid;
	if (pgid < 0)
		return (EINVAL);

	newpgrp = uma_zalloc(pgrp_zone, M_WAITOK);
again:
	error = pdconf_find(td, uap->procfd, &p, &fp_pd);
	if (error != 0) {
		uma_zfree(pgrp_zone, newpgrp);
		return (error);
	}
	PROC_UNLOCK(p);

	sx_xlock(&proctree_lock);
	/*
	 * The embryo must be in the caller's session, which it inherited at
	 * creation.  The pid-based target validation setpgid(2) performs --
	 * inferior(), p_cansee(), and the P_EXEC "already exec'd" gate -- does
	 * not apply here: the process is named by a descriptor the caller
	 * holds, and an embryo has by definition not yet exec'd.  The remaining
	 * setpgid(2) rules are identical, so defer to the shared core.
	 */
	if (p->p_pgrp == NULL || p->p_session != curp->p_session) {
		error = EPERM;
		goto done;
	}
	error = do_setpgid(curp, p, pgid, &newpgrp);
done:
	KASSERT(error == 0 || newpgrp != NULL,
	    ("pdsetpgid failed and newpgrp is NULL"));
	sx_xunlock(&proctree_lock);
	fdrop(fp_pd, td);
	if (error == ERESTART)
		goto again;
	uma_zfree(pgrp_zone, newpgrp);
	return (error);
}

/*
 * Set the scheduling parameters, and optionally the scheduling policy, of an
 * embryonic process.
 *
 * These are sched_setparam(2) and sched_setscheduler(2) aimed at a process
 * that cannot call them for itself.  Both of those already accept a pid
 * other than the caller's and apply p_cansched(9) to it, so the permission
 * model is unchanged; only the way the target is named differs.  Setting a
 * policy additionally requires PRIV_SCHED_SETPOLICY, as it does there.
 *
 * An embryo is single-threaded, so the process's only thread is the one
 * configured -- matching what sched_setparam(2) does when given a pid, and
 * what the new program will see when it starts.
 */
int
sys_pdsetschedparam(struct thread *td, struct pdsetschedparam_args *uap)
{
	struct sched_param param;
	struct proc *p;
	struct file *fp_pd;
	int error;

	error = copyin(uap->param, &param, sizeof(param));
	if (error != 0)
		return (error);

	error = pdconf_find(td, uap->procfd, &p, &fp_pd);
	if (error != 0)
		return (error);

	error = kern_sched_setparam(td, FIRST_THREAD_IN_PROC(p), &param);
	PROC_UNLOCK(p);
	fdrop(fp_pd, td);
	return (error);
}

int
sys_pdsetscheduler(struct thread *td, struct pdsetscheduler_args *uap)
{
	struct sched_param param;
	struct proc *p;
	struct file *fp_pd;
	int error;

	error = copyin(uap->param, &param, sizeof(param));
	if (error != 0)
		return (error);

	error = pdconf_find(td, uap->procfd, &p, &fp_pd);
	if (error != 0)
		return (error);

	error = kern_sched_setscheduler(td, FIRST_THREAD_IN_PROC(p),
	    uap->policy, &param);
	PROC_UNLOCK(p);
	fdrop(fp_pd, td);
	return (error);
}

/*
 * pdresetids: drop an embryonic process to its real user and group ids.
 *
 * This is what POSIX_SPAWN_RESETIDS asks for, applied from the outside.
 */
int
sys_pdresetids(struct thread *td, struct pdresetids_args *uap)
{
	struct proc *p;
	struct file *fp_pd;
	cap_rights_t rights;
	int error;

	error = procdesc_find(td, uap->procfd,
	    cap_rights_init(&rights, CAP_PDSETFD), &p, &fp_pd);
	if (error != 0)
		return (error);

	if (p->p_state != PRS_NEW || (p->p_flag & P_INEXEC) == 0) {
		PROC_UNLOCK(p);
		fdrop(fp_pd, td);
		return (EINVAL);
	}
	PROC_UNLOCK(p);

	error = pdresetids_proc(p);
	fdrop(fp_pd, td);
	return (error);
}

/*
 * Submit an embryonic process to the scheduler, promoting it to a regular
 * process.
 *
 * This is only reachable for a process that has a program but was not
 * started by the call that gave it one; pdexec(2) starts what it loads.
 */
int
sys_pdstart(struct thread *td, struct pdstart_args *uap)
{
	struct proc *p;
	struct file *fp_pd;
	cap_rights_t rights;
	int error;

	error = procdesc_find(td, uap->procfd,
	    cap_rights_init(&rights, CAP_PDKILL), &p, &fp_pd);
	if (error != 0)
		return (error);

	/* Must be an embryonic process with an executable loaded. */
	if (p->p_state != PRS_NEW || (p->p_flag & P_INEXEC) == 0 ||
	    p->p_textvp == NULL) {
		PROC_UNLOCK(p);
		fdrop(fp_pd, td);
		return (EINVAL);
	}

	pdstart_proc(p);
	fdrop(fp_pd, td);
	return (0);
}
