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
	 * As for pdfork(2), CAP_PTRACE and CAP_PROCCTL are withheld unless the
	 * caller asks for them: a descriptor must be deliberately prepared
	 * before it confers the authority to debug or control the process,
	 * which matters all the more here, where the descriptor is routinely
	 * handed to someone else to start.
	 */
	filecaps_fill(&fcaps);
	if ((flags & PD_PTRACE_CAP) == 0)
		cap_rights_clear(&fcaps.fc_rights, CAP_PTRACE);
	if ((flags & PD_PROCCTL_CAP) == 0)
		cap_rights_clear(&fcaps.fc_rights, CAP_PROCCTL);
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
	/*
	 * Start with an empty working-directory descriptor: NULL cwd and root,
	 * default umask.  Like the empty descriptor table, this is deliberate --
	 * the directories an embryo runs with are opt-in, established by
	 * pdchdir(2)/pdchroot(2), not inherited.  A process that never sets them
	 * has no valid cwd or root, so a caller reproducing fork(2)+execve(2)
	 * inheritance must set them explicitly (see pdchdir(2)'s AT_FDCWD and
	 * pdchroot(2)'s AT_FDROOT).
	 */
	newpd = pdinit(NULL, false);
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

/*
 * Copy in a cap_rights_t from userspace and validate it, as
 * cap_rights_limit(2) does.
 */
static int
pdsetfd_copyin_rights(const cap_rights_t *urights, cap_rights_t *rights)
{
	int error, version;

	cap_rights_init_zero(rights);
	error = copyin(urights, rights, sizeof(rights->cr_rights[0]));
	if (error != 0)
		return (error);
	version = CAPVER(rights);
	if (version != CAP_RIGHTS_VERSION_00)
		return (EINVAL);
	error = copyin(urights, rights,
	    sizeof(rights->cr_rights[0]) * CAPARSIZE(rights));
	if (error != 0)
		return (error);
	if (CAPVER(rights) != version)
		return (EINVAL);
	if (!cap_rights_is_valid(rights))
		return (EINVAL);
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
	 * An explicit rights argument narrows what the installed descriptor
	 * carries.  It may only remove rights the caller holds on localfd,
	 * never add any, so it must name a subset of them.
	 */
	if (uap->rights != NULL) {
		cap_rights_t reqrights;

		error = pdsetfd_copyin_rights(uap->rights, &reqrights);
		if (error == 0 &&
		    !cap_rights_contains(&fcaps.fc_rights, &reqrights))
			error = ENOTCAPABLE;
		if (error != 0) {
			filecaps_free(&fcaps);
			fdrop(fp, td);
			fdrop(fp_pd, td);
			return (error);
		}
		fcaps.fc_rights = reqrights;
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
	struct pwddesc *pdp;
	struct pwd *pwd;
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
	 * The program needs a working directory and a root to resolve paths --
	 * the dynamic linker's interpreter is looked up against the root, for
	 * one.  An embryo starts with neither (see kern_pdnew()), so refuse to
	 * start one whose cwd and root have not been set, whether by
	 * pdchdir(2)/pdchroot(2) or, for a process that will not use paths, by
	 * pdcap_enter(2).
	 */
	pdp = p2->p_pd;
	PWDDESC_XLOCK(pdp);
	pwd = pwd_hold_pwddesc(pdp);
	PWDDESC_XUNLOCK(pdp);
	error = (pwd == NULL || pwd->pwd_cdir == NULL || pwd->pwd_rdir == NULL) ?
	    EINVAL : 0;
	if (pwd != NULL)
		pwd_drop(pwd);
	if (error != 0) {
		fdrop(fp_pd, td);
		return (error);
	}

	/*
	 * Two forms, chosen by the caller in sys_pdexec():
	 *
	 *   - By path (execfd < 0): args->fname is set, and the exec below
	 *     resolves it in the target, against the embryo's own working
	 *     directory and root.  Nothing is installed into the target, so
	 *     the program that runs sees no extra descriptor.
	 *
	 *   - By descriptor (execfd >= 0): the executable is installed into
	 *     the target, as fexecve(2) runs an already-open file.  It goes in
	 *     without close-on-exec, exactly as fexecve(2) leaves the file open
	 *     across the exec, so that a #! script read back by its interpreter
	 *     through /dev/fd/N still resolves; it is therefore visible to the
	 *     program that runs, as it is with fexecve(2).  The rights the
	 *     caller retained on it are preserved rather than granting the
	 *     child full rights.
	 */
	if (execfd >= 0) {
		error = fget_cap(td, execfd, &cap_fexecve_rights, NULL, &efp,
		    &fcaps);
		if (error != 0) {
			fdrop(fp_pd, td);
			return (error);
		}
		error = finstall_at(td, p2, efp, execfd, 0, &fcaps);
		if (error != 0)
			filecaps_free(&fcaps);
		fdrop(efp, td);
		if (error != 0) {
			fdrop(fp_pd, td);
			return (error);
		}
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
	const char *fname;
	int error, execfd;

	/* AT_EMPTY_PATH selects the by-descriptor form; no other flag exists. */
	if ((uap->flags & ~AT_EMPTY_PATH) != 0)
		return (EINVAL);

	if ((uap->flags & AT_EMPTY_PATH) != 0) {
		/*
		 * fexecve(2) form: run the file named by fd.  path is ignored,
		 * and the descriptor is installed into the target.
		 */
		fname = NULL;
		execfd = uap->fd;
	} else {
		/*
		 * execve(2) form: run the program named by path, resolved in
		 * the target.  A real dirfd would need execveat(2)-style
		 * resolution the kernel lacks, so only AT_FDCWD is accepted.
		 */
		if (uap->fd != AT_FDCWD)
			return (EINVAL);
		fname = uap->path;
		execfd = -1;
	}

	error = exec_copyin_args(&args, fname, uap->argv, uap->envv);
	if (error != 0)
		return (error);

	error = kern_pdexec(td, uap->procfd, execfd, &args);
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
	struct file *fp_pd;
	struct vnode *vp;
	int error;

	error = chdir_getvp(td, uap->dirfd, &vp);
	if (error != 0)
		return (error);
	error = pdconf_find(td, uap->procfd, &p, &fp_pd);
	if (error != 0) {
		vrele(vp);
		return (error);
	}
	PROC_UNLOCK(p);
	/* Consumes the reference taken above. */
	pwd_chdir(p, vp);
	fdrop(fp_pd, td);
	return (0);
}

/*
 * Set the root directory of an embryonic process.
 *
 * chroot_getvp() resolves dirfd -- AT_FDROOT propagates the caller's own root
 * unprivileged, any other descriptor is a privileged chroot(2) to a new one --
 * and pwd_chroot() installs it in the embryo, applying the same
 * open-directory-descriptor restriction chroot(2) does against the embryo's
 * own descriptor table.
 */
int
sys_pdchroot(struct thread *td, struct pdchroot_args *uap)
{
	struct proc *p;
	struct file *fp_pd;
	struct vnode *vp;
	int error;

	error = chroot_getvp(td, uap->dirfd, &vp);
	if (error != 0)
		return (error);
	error = pdconf_find(td, uap->procfd, &p, &fp_pd);
	if (error != 0) {
		vrele(vp);
		return (error);
	}
	PROC_UNLOCK(p);
	error = pwd_chroot(p, vp);
	vrele(vp);
	fdrop(fp_pd, td);
	return (error);
}

/*
 * Put an embryonic process into capability mode.
 *
 * This is cap_enter(2) aimed at a process that cannot call it for itself: the
 * embryo enters Capsicum capability mode before it ever runs, so a caller can
 * hand a sandboxed process its descriptors and program without the process
 * having to confine itself.  Like cap_enter(2) it requires no privilege.
 *
 * A capability-mode process resolves paths only against descriptors, so it
 * never consults its working directory or root -- but pdexec(2) still requires
 * both be set.  Give it the system root for any it has not been assigned, since
 * the value cannot matter to a process that will never look at it.
 */
int
sys_pdcap_enter(struct thread *td, struct pdcap_enter_args *uap)
{
	struct proc *p;
	struct file *fp_pd;
	struct ucred *newcred, *oldcred;
	bool capmode;
	int error;

	error = pdconf_find(td, uap->procfd, &p, &fp_pd);
	if (error != 0)
		return (error);
	capmode = (p->p_ucred->cr_flags & CRED_FLAG_CAPMODE) != 0;
	PROC_UNLOCK(p);

	if (!capmode) {
		newcred = crget();
		PROC_LOCK(p);
		oldcred = crcopysafe(p, newcred);
		newcred->cr_flags |= CRED_FLAG_CAPMODE;
		proc_set_cred(p, newcred);
		PROC_UNLOCK(p);
		crfree(oldcred);
	}

	pwd_ensure_dirs(p);
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
 * own arrangements.  An embryo is configured before pdexec(2) gives it an
 * image, so it has never exec'd, P_EXEC is never set, and there are no such
 * arrangements to disturb; the creator remains the only party that has ever
 * acted on the process.
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
	error = do_setpgid(curp, p, pgid, &newpgrp);
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
