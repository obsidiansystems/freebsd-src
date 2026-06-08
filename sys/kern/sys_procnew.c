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
 * Embryonic process creation: proc_new(), proc_setfd(), proc_start().
 *
 * proc_new() creates an unscheduled process with a loaded executable,
 * returning a process descriptor fd.  proc_setfd() installs file
 * descriptors into the embryonic process.  proc_start() submits it
 * to the scheduler.
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
#include <sys/sysctl.h>
#include <sys/sysproto.h>
#include <sys/vnode.h>

#include <security/audit/audit.h>
#include <security/mac/mac_framework.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/uma.h>

SDT_PROVIDER_DECLARE(proc);

/*
 * kern_proc_new: create an embryonic process with a loaded executable.
 *
 * This is the single combined operation: allocate a minimal process,
 * load the executable, return a process descriptor.  If anything
 * fails, all resources are cleaned up.
 *
 * The resulting process is in PRS_NEW with P_INEXEC set.  It must
 * be started with proc_start() after optional proc_setfd() calls.
 */
int
kern_proc_new(struct thread *td, int exec_fd, struct image_args *args,
    int flags, int *fdp)
{
	struct proc *p1, *p2;
	struct thread *td2;
	struct nameidata nd;
	struct filedesc *newfd;
	struct pwddesc *newpd;
	struct sigacts *newsigacts;
	struct ucred *oldcred;
	struct uidinfo *euip = NULL;
	struct file *fp_procdesc;
	uintptr_t stack_base;
	struct image_params image_params, *imgp;
	struct vattr attr;
	struct pargs *newargs = NULL;
	struct vnode *newtextvp;
	struct vnode *newtextdvp;
	char *newbinname;
	bool proc_allocated;
#ifdef MAC
	struct label *interpvplabel = NULL;
	bool will_transition;
#endif
	int error, fd_num;

	p1 = td->td_proc;
	p2 = NULL;
	fp_procdesc = NULL;
	fd_num = -1;
	proc_allocated = false;

	/* ============================================================
	 * Phase 1: Validate the executable.
	 *
	 * Do this before allocating the process so that bad
	 * executables fail cheaply.
	 * ============================================================ */

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

	/* ============================================================
	 * Phase 2: Allocate the embryonic process.
	 *
	 * Now that we know the executable is valid, allocate the
	 * process.  The vmspace is left NULL; exec_new_vmspace()
	 * (called by the image activator) will create the correct
	 * one for the executable's ABI.
	 * ============================================================ */

	/* Allocate the process descriptor fd in the parent. */
	error = procdesc_falloc(td, &fp_procdesc, &fd_num, flags, NULL);
	if (error != 0)
		goto exec_fail_dealloc;

	error = fork_alloc_proc(td, 0, &p2, &td2);
	if (error != 0) {
		fdclose(td, fp_procdesc, fd_num);
		fdrop(fp_procdesc, td);
		goto exec_fail_dealloc;
	}

	fork_register_proc(p2, td2, 0);

	/* Fresh file descriptors — empty table. */
	newpd = pdinit(p1->p_pd, false);
	newfd = fdinit();
	newsigacts = sigacts_alloc();

	bzero(&p2->p_startzero,
	    __rangeof(struct proc, p_startzero, p_endzero));

	PROC_LOCK(p2);

	bzero(&td2->td_startzero,
	    __rangeof(struct thread, td_startzero, td_endzero));
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

	p2->p_fd = newfd;
	p2->p_fdtol = NULL;
	p2->p_pd = newpd;
	p2->p_vmspace = NULL;	/* exec_new_vmspace will create it */

	lim_fork(p1, p2);
	thread_cow_get_proc(td2, p2);
	pstats_fork(p1->p_stats, p2->p_stats);

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

	/*
	 * Set up kernel stack and PCB via cpu_fork.  This copies the
	 * parent's trapframe/PCB, which is wasted work since
	 * sv_setregs will overwrite all user registers.  However,
	 * cpu_fork also sets up the kernel-side fork_trampoline
	 * which is needed for the thread to enter userspace.
	 *
	 * TODO: An embryonic-specific variant that only sets up the
	 * trampoline without copying user register state would avoid
	 * this waste.
	 */
	cpu_fork(td, p2, td2, RFPROC);

	/* Set up the process descriptor. */
	procdesc_new(p2, flags);

	EVENTHANDLER_DIRECT_INVOKE(process_fork, p1, p2, RFPROC);
	SDT_PROBE3(proc, , , create, p2, p1, RFPROC);

	procdesc_finit(p2->p_procdesc, fp_procdesc);
	fdrop(fp_procdesc, td);
	fp_procdesc = NULL;

	racct_proc_fork_done(p2);

	proc_allocated = true;

	/* ============================================================
	 * Phase 3: Load the executable into the embryonic process.
	 *
	 * The image is already mapped (from Phase 1).  Now wire it
	 * up to the process and run the image activators to create
	 * the vmspace.
	 * ============================================================ */

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
		/* Resolve the interpreter. */
		if (imgp->interpreter_vp) {
			exec_interpreter_vp(imgp, &newtextvp);
		} else {
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

	newargs = exec_cache_args(imgp->args);

	vn_lock(imgp->vp, LK_SHARED | LK_RETRY);

	PROC_LOCK(p2);

	exec_set_comm(imgp, NULL, 0);

	exec_install_setid(imgp, td, &oldcred
#ifdef MAC
	    , will_transition, interpvplabel
#endif
	    );

	exec_finalize(imgp, newtextvp, &newbinname, &newargs, stack_base);

	/* ============================================================
	 * Cleanup — runs on both success and failure paths.
	 * ============================================================ */
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
	 * If exec failed, destroy the embryonic process.
	 */
	if (error != 0 && proc_allocated) {
		proc_destroy_embryonic(p2);
		kern_close(td, fd_num);
		return (error);
	}

	if (error != 0)
		return (error);

	*fdp = fd_num;
	return (0);
}

int
sys_proc_new(struct thread *td, struct proc_new_args *uap)
{
	struct image_args args;
	int error, procfd;

	error = exec_copyin_args(&args, NULL, uap->argv, uap->envv);
	if (error != 0)
		return (error);

	args.fd = uap->fd;

	error = kern_proc_new(td, uap->fd, &args, uap->flags, &procfd);
	if (error != 0)
		return (error);

	error = copyout(&procfd, uap->procfdp, sizeof(procfd));
	if (error != 0) {
		kern_close(td, procfd);
		return (error);
	}

	td->td_retval[0] = 0;
	return (0);
}

int
sys_proc_setfd(struct thread *td, struct proc_setfd_args *uap)
{
	struct proc *p;
	struct file *fp;
	struct filedesc *fdp;
	cap_rights_t rights;
	int error;

	/* Look up the embryonic process via its procdesc. */
	error = procdesc_find(td, uap->procfd,
	    cap_rights_init(&rights, CAP_PDKILL), &p);
	if (error != 0)
		return (error);

	/* Must be an embryonic (P_INEXEC, PRS_NEW) process. */
	if (p->p_state != PRS_NEW || (p->p_flag & P_INEXEC) == 0) {
		PROC_UNLOCK(p);
		return (EINVAL);
	}
	PROC_UNLOCK(p);

	/* Look up the fd to install, from the caller's fd table. */
	error = fget(td, uap->parent_fd,
	    cap_rights_init(&rights), &fp);
	if (error != 0)
		return (error);

	/* Install into the embryonic process's fd table. */
	fdp = p->p_fd;
	FILEDESC_XLOCK(fdp);

	/* Grow the table if needed. */
	if (uap->child_fd >= fdp->fd_nfiles)
		fdgrowtable(fdp, uap->child_fd + 1);

	/* If slot is occupied, close the existing fd. */
	if (fdp->fd_ofiles[uap->child_fd].fde_file != NULL) {
		struct file *oldfp;

		oldfp = fdp->fd_ofiles[uap->child_fd].fde_file;
		fdefree_last(&fdp->fd_ofiles[uap->child_fd]);
		FILEDESC_XUNLOCK(fdp);
		fdrop(oldfp, td);
		FILEDESC_XLOCK(fdp);
	}

	fhold(fp);
	_finstall(fdp, fp, uap->child_fd, 0, NULL);
	FILEDESC_XUNLOCK(fdp);

	fdrop(fp, td);
	return (0);
}

int
sys_proc_start(struct thread *td, struct proc_start_args *uap)
{
	struct proc *p;
	struct thread *td2;
	cap_rights_t rights;
	int error;

	/* Look up the embryonic process via its procdesc. */
	error = procdesc_find(td, uap->procfd,
	    cap_rights_init(&rights, CAP_PDKILL), &p);
	if (error != 0)
		return (error);

	/* Must be an embryonic process with an executable loaded. */
	if (p->p_state != PRS_NEW || (p->p_flag & P_INEXEC) == 0) {
		PROC_UNLOCK(p);
		return (EINVAL);
	}
	if (p->p_textvp == NULL) {
		PROC_UNLOCK(p);
		return (EINVAL);
	}

	/* Clear P_INEXEC and transition to normal state. */
	p->p_flag &= ~P_INEXEC;

	PROC_SLOCK(p);
	p->p_state = PRS_NORMAL;
	PROC_SUNLOCK(p);

	microuptime(&p->p_stats->p_start);

	PROC_UNLOCK(p);

	/* Schedule the process's thread. */
	td2 = FIRST_THREAD_IN_PROC(p);
	thread_lock(td2);
	TD_SET_CAN_RUN(td2);
	sched_add(td2, SRQ_BORING);

	return (0);
}
