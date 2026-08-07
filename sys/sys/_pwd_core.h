/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 John Ericson, Obsidian Systems
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

#ifndef _SYS__PWD_CORE_H_
#define	_SYS__PWD_CORE_H_

struct vnode;

/*
 * The set of directories a path lookup is resolved against: where a relative
 * path starts, and the two boundaries an absolute path or a ".." traversal
 * stops at.
 *
 * Two things carry one of these:
 *
 * - struct pwd holds the process's own, which is what a lookup resolves
 *   against by default, plus optionally a second set retained for core
 *   dumping; see <sys/filedesc.h>.
 *
 * - struct nameidata holds the working copy for a single lookup attempt,
 *   derived afresh each time namei() restarts; see <sys/namei.h>.
 *
 * It lives in its own header so that neither of those has to depend on the
 * other merely to embed it by value.
 */
struct pwd_core {
	struct	vnode	*pwd_core_cdir;	/* current/starting directory */
	struct	vnode	*pwd_core_rdir;	/* root directory */
	struct	vnode	*pwd_core_jdir;	/* jail root directory */
};

#endif /* !_SYS__PWD_CORE_H_ */
