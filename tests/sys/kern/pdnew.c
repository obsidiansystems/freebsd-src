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
 * Tests for the embryonic-process model.  An embryo is created with
 * pdrfork(2) + RFEMBRYO, configured through the pd* family --- pdsetfd(),
 * pdsetfdrange(), pdchdir(), pdchroot(), pdcap_enter(), pdsetpgid(), ... ---
 * and then given a program and run with pdexec(2).  An embryo inherits
 * nothing, so a runnable one has to be told at least its working directory
 * and its root; pdexec(2) refuses to run one that has neither.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/mount.h>
#include <sys/procdesc.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

/*
 * Helper: open an executable by path and return the fd.
 */
static int
open_exec(const char *path)
{
	int fd;

	/*
	 * O_RDONLY, not O_EXEC: exec-by-fd checks the file's execute
	 * permission, not the descriptor's access mode, and a shebang
	 * interpreter must be able to read the script back through
	 * /dev/fd/N -- which requires a readable descriptor.
	 */
	fd = open(path, O_RDONLY);
	ATF_REQUIRE_MSG(fd >= 0, "open(%s): %s", path, strerror(errno));
	return (fd);
}

/*
 * Create an embryonic process with pdrfork(2) and RFEMBRYO, returning its
 * process descriptor.  The embryo inherits nothing: no image, an empty
 * descriptor table, and neither a working directory nor a root.
 */
static int
pdembryo_bare(void)
{
	int procfd;
	pid_t pid;

	pid = pdrfork(&procfd, 0, RFEMBRYO);
	ATF_REQUIRE_MSG(pid > 0, "pdrfork(RFEMBRYO): %s", strerror(errno));
	return (procfd);
}

/*
 * As pdembryo_bare(), but give the embryo the caller's own working directory
 * and root (AT_FDCWD / AT_FDROOT), which needs no privilege.  The result is
 * runnable: pdexec(2) will accept it.  Most tests want this.
 */
static int
pdembryo(void)
{
	int error, procfd;

	procfd = pdembryo_bare();
	error = pdchdir(procfd, AT_FDCWD);
	ATF_REQUIRE_MSG(error == 0, "pdchdir(AT_FDCWD): %s", strerror(errno));
	error = pdchroot(procfd, AT_FDROOT);
	ATF_REQUIRE_MSG(error == 0, "pdchroot(AT_FDROOT): %s", strerror(errno));
	return (procfd);
}

/*
 * Basic lifecycle: create, exec, wait.  Run /usr/bin/true, exit status 0.
 */
ATF_TC_WITHOUT_HEAD(basic_true);
ATF_TC_BODY(basic_true, tc)
{
	char *argv[] = { __DECONST(char *, "true"), NULL };
	char *envv[] = { NULL };
	int error, execfd, procfd, status;

	execfd = open_exec("/usr/bin/true");
	procfd = pdembryo();

	error = pdexec(procfd, execfd, "", argv, envv, AT_EMPTY_PATH);
	ATF_REQUIRE_MSG(error == 0, "pdexec: %s", strerror(errno));
	ATF_REQUIRE(close(execfd) == 0);

	error = pdwait(procfd, &status, WEXITED, NULL, NULL);
	ATF_REQUIRE_MSG(error == 0, "pdwait: %s", strerror(errno));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "unexpected exit status: %#x", status);

	ATF_REQUIRE(close(procfd) == 0);
}

/*
 * Run /usr/bin/false and verify exit status 1.
 */
ATF_TC_WITHOUT_HEAD(basic_false);
ATF_TC_BODY(basic_false, tc)
{
	char *argv[] = { __DECONST(char *, "false"), NULL };
	char *envv[] = { NULL };
	int error, execfd, procfd, status;

	execfd = open_exec("/usr/bin/false");
	procfd = pdembryo();

	error = pdexec(procfd, execfd, "", argv, envv, AT_EMPTY_PATH);
	ATF_REQUIRE_MSG(error == 0, "pdexec: %s", strerror(errno));
	ATF_REQUIRE(close(execfd) == 0);

	error = pdwait(procfd, &status, WEXITED, NULL, NULL);
	ATF_REQUIRE_MSG(error == 0, "pdwait: %s", strerror(errno));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 1,
	    "unexpected exit status: %#x", status);

	ATF_REQUIRE(close(procfd) == 0);
}

/*
 * pdexec(2) by path rather than by descriptor: without AT_EMPTY_PATH the
 * kernel resolves the program in the embryo, against the directories it was
 * given, and installs no descriptor of its own -- the form posix_spawn(3)
 * uses so the spawned process's table stays clean.  A real dirfd is rejected
 * for now, since only AT_FDCWD resolution is implemented.
 */
ATF_TC_WITHOUT_HEAD(exec_by_path);
ATF_TC_BODY(exec_by_path, tc)
{
	char *argv[] = { __DECONST(char *, "true"), NULL };
	char *envv[] = { NULL };
	int error, procfd, status;

	/* A real dirfd with a path is not supported yet. */
	procfd = pdembryo();
	error = pdexec(procfd, STDIN_FILENO, "/usr/bin/true", argv, envv, 0);
	ATF_REQUIRE_MSG(error == -1, "pdexec with a real dirfd should fail");
	ATF_REQUIRE_MSG(errno == EINVAL,
	    "unexpected errno: %d (%s)", errno, strerror(errno));
	ATF_REQUIRE(close(procfd) == 0);

	procfd = pdembryo();
	error = pdexec(procfd, AT_FDCWD, "/usr/bin/true", argv, envv, 0);
	ATF_REQUIRE_MSG(error == 0, "pdexec by path: %s", strerror(errno));

	error = pdwait(procfd, &status, WEXITED, NULL, NULL);
	ATF_REQUIRE_MSG(error == 0, "pdwait: %s", strerror(errno));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "unexpected exit status: %#x", status);

	ATF_REQUIRE(close(procfd) == 0);
}

/*
 * Install stdout with pdsetfd(2) before the exec, and read the output.
 */
ATF_TC_WITHOUT_HEAD(setfd_stdout);
ATF_TC_BODY(setfd_stdout, tc)
{
	char buf[128];
	char *argv[] = { __DECONST(char *, "echo"),
	    __DECONST(char *, "hello"), NULL };
	char *envv[] = { NULL };
	int error, execfd, procfd, status, pipefd[2];
	ssize_t n;

	ATF_REQUIRE(pipe(pipefd) == 0);
	execfd = open_exec("/bin/echo");
	procfd = pdembryo();

	error = pdsetfd(procfd, STDOUT_FILENO, pipefd[1], NULL);
	ATF_REQUIRE_MSG(error == 0, "pdsetfd: %s", strerror(errno));
	ATF_REQUIRE(close(pipefd[1]) == 0);

	error = pdexec(procfd, execfd, "", argv, envv, AT_EMPTY_PATH);
	ATF_REQUIRE_MSG(error == 0, "pdexec: %s", strerror(errno));
	ATF_REQUIRE(close(execfd) == 0);

	n = read(pipefd[0], buf, sizeof(buf) - 1);
	ATF_REQUIRE_MSG(n > 0, "read: %s", strerror(errno));
	buf[n] = '\0';
	ATF_REQUIRE_MSG(strcmp(buf, "hello\n") == 0,
	    "unexpected output: '%s'", buf);
	ATF_REQUIRE(close(pipefd[0]) == 0);

	error = pdwait(procfd, &status, WEXITED, NULL, NULL);
	ATF_REQUIRE_MSG(error == 0, "pdwait: %s", strerror(errno));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	ATF_REQUIRE(close(procfd) == 0);
}

/*
 * Install stdin and stdout with pdsetfd(2), pipe data through /bin/cat.
 */
ATF_TC_WITHOUT_HEAD(setfd_stdin);
ATF_TC_BODY(setfd_stdin, tc)
{
	char buf[128];
	char *argv[] = { __DECONST(char *, "cat"), NULL };
	char *envv[] = { NULL };
	int error, execfd, procfd, status, in_pipe[2], out_pipe[2];
	ssize_t n;

	ATF_REQUIRE(pipe(in_pipe) == 0);
	ATF_REQUIRE(pipe(out_pipe) == 0);
	execfd = open_exec("/bin/cat");
	procfd = pdembryo();

	error = pdsetfd(procfd, STDIN_FILENO, in_pipe[0], NULL);
	ATF_REQUIRE_MSG(error == 0, "pdsetfd stdin: %s", strerror(errno));
	ATF_REQUIRE(close(in_pipe[0]) == 0);
	error = pdsetfd(procfd, STDOUT_FILENO, out_pipe[1], NULL);
	ATF_REQUIRE_MSG(error == 0, "pdsetfd stdout: %s", strerror(errno));
	ATF_REQUIRE(close(out_pipe[1]) == 0);

	error = pdexec(procfd, execfd, "", argv, envv, AT_EMPTY_PATH);
	ATF_REQUIRE_MSG(error == 0, "pdexec: %s", strerror(errno));
	ATF_REQUIRE(close(execfd) == 0);

	ATF_REQUIRE(write(in_pipe[1], "world\n", 6) == 6);
	ATF_REQUIRE(close(in_pipe[1]) == 0);

	n = read(out_pipe[0], buf, sizeof(buf) - 1);
	ATF_REQUIRE_MSG(n > 0, "read: %s", strerror(errno));
	buf[n] = '\0';
	ATF_REQUIRE_MSG(strcmp(buf, "world\n") == 0,
	    "unexpected output: '%s'", buf);
	ATF_REQUIRE(close(out_pipe[0]) == 0);

	error = pdwait(procfd, &status, WEXITED, NULL, NULL);
	ATF_REQUIRE_MSG(error == 0, "pdwait: %s", strerror(errno));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	ATF_REQUIRE(close(procfd) == 0);
}

/*
 * A file that is executable but has no recognized format cannot be loaded.
 * pdexec(2) does not perform the exec itself -- it arms the target and
 * returns success, then the target runs and its exec fails there.  A process
 * that has never run has nothing to fall back to, so it dies with SIGABRT,
 * which the creator learns of through pdwait(2).
 */
ATF_TC_WITHOUT_HEAD(error_noexec);
ATF_TC_BODY(error_noexec, tc)
{
	char *argv[] = { __DECONST(char *, "noexec"), NULL };
	char *envv[] = { NULL };
	char path[] = "/tmp/pdnew_noexec.XXXXXX";
	int error, fd, procfd, status, tmpfd;

	tmpfd = mkstemp(path);
	ATF_REQUIRE_MSG(tmpfd >= 0, "mkstemp: %s", strerror(errno));
	ATF_REQUIRE(write(tmpfd, "not an executable\n", 18) == 18);
	ATF_REQUIRE(fchmod(tmpfd, 0755) == 0);
	ATF_REQUIRE(close(tmpfd) == 0);

	fd = open_exec(path);
	procfd = pdembryo();

	/* The exec happens in the target, so pdexec(2) itself still succeeds. */
	error = pdexec(procfd, fd, "", argv, envv, AT_EMPTY_PATH);
	ATF_REQUIRE_MSG(error == 0, "pdexec: %s", strerror(errno));

	error = pdwait(procfd, &status, WEXITED, NULL, NULL);
	ATF_REQUIRE_MSG(error == 0, "pdwait: %s", strerror(errno));
	ATF_REQUIRE_MSG(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT,
	    "expected SIGABRT from the failed exec, got status %#x", status);

	ATF_REQUIRE(close(procfd) == 0);
	ATF_REQUIRE(close(fd) == 0);
	unlink(path);
}

/*
 * pdexec(2) with an invalid process descriptor fails with EBADF.
 */
ATF_TC_WITHOUT_HEAD(error_bad_procfd);
ATF_TC_BODY(error_bad_procfd, tc)
{
	char *argv[] = { __DECONST(char *, "true"), NULL };
	char *envv[] = { NULL };
	int error, execfd;

	execfd = open_exec("/usr/bin/true");
	error = pdexec(999, execfd, "", argv, envv, AT_EMPTY_PATH);
	ATF_REQUIRE_MSG(error == -1, "pdexec should have failed");
	ATF_REQUIRE_MSG(errno == EBADF,
	    "unexpected errno: %d (%s)", errno, strerror(errno));
	ATF_REQUIRE(close(execfd) == 0);
}

/*
 * An embryo starts with neither a working directory nor a root, and pdexec(2)
 * refuses to run one that is missing either: all three of "neither", "cwd
 * only" and "root only" must fail with EINVAL.
 */
ATF_TC_WITHOUT_HEAD(exec_requires_dirs);
ATF_TC_BODY(exec_requires_dirs, tc)
{
	char *argv[] = { __DECONST(char *, "true"), NULL };
	char *envv[] = { NULL };
	int error, execfd, procfd;

	execfd = open_exec("/usr/bin/true");

	/* Neither cwd nor root. */
	procfd = pdembryo_bare();
	error = pdexec(procfd, execfd, "", argv, envv, AT_EMPTY_PATH);
	ATF_REQUIRE_MSG(error == -1, "pdexec should fail with no dirs");
	ATF_REQUIRE_MSG(errno == EINVAL,
	    "no dirs: unexpected errno %d (%s)", errno, strerror(errno));
	ATF_REQUIRE(close(procfd) == 0);

	/* Working directory only. */
	procfd = pdembryo_bare();
	ATF_REQUIRE(pdchdir(procfd, AT_FDCWD) == 0);
	error = pdexec(procfd, execfd, "", argv, envv, AT_EMPTY_PATH);
	ATF_REQUIRE_MSG(error == -1, "pdexec should fail with cwd but no root");
	ATF_REQUIRE_MSG(errno == EINVAL,
	    "cwd only: unexpected errno %d (%s)", errno, strerror(errno));
	ATF_REQUIRE(close(procfd) == 0);

	/* Root only. */
	procfd = pdembryo_bare();
	ATF_REQUIRE(pdchroot(procfd, AT_FDROOT) == 0);
	error = pdexec(procfd, execfd, "", argv, envv, AT_EMPTY_PATH);
	ATF_REQUIRE_MSG(error == -1, "pdexec should fail with root but no cwd");
	ATF_REQUIRE_MSG(errno == EINVAL,
	    "root only: unexpected errno %d (%s)", errno, strerror(errno));
	ATF_REQUIRE(close(procfd) == 0);

	ATF_REQUIRE(close(execfd) == 0);
}

/*
 * pdchdir(2) sets the embryo's working directory by descriptor.  A shell run
 * in the embryo writes a marker file by a relative path; it lands in the
 * directory we chose, proving that was its cwd.
 */
ATF_TC_WITHOUT_HEAD(chdir_sets_cwd);
ATF_TC_BODY(chdir_sets_cwd, tc)
{
	char *argv[] = { __DECONST(char *, "sh"), __DECONST(char *, "-c"),
	    __DECONST(char *, "echo marked > cwdmarker"), NULL };
	char *envv[] = { NULL };
	char dir[] = "/tmp/pdnew_cwd.XXXXXX";
	char marker[MAXPATHLEN];
	struct stat sb;
	int devnull, dirfd, error, execfd, procfd, status;

	ATF_REQUIRE_MSG(mkdtemp(dir) != NULL, "mkdtemp: %s", strerror(errno));
	dirfd = open(dir, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE_MSG(dirfd >= 0, "open(%s): %s", dir, strerror(errno));
	execfd = open_exec("/bin/sh");
	procfd = pdembryo_bare();

	/* cwd = the temp directory (by descriptor); root = the caller's own. */
	error = pdchdir(procfd, dirfd);
	ATF_REQUIRE_MSG(error == 0, "pdchdir: %s", strerror(errno));
	error = pdchroot(procfd, AT_FDROOT);
	ATF_REQUIRE_MSG(error == 0, "pdchroot(AT_FDROOT): %s", strerror(errno));

	devnull = open("/dev/null", O_RDWR);
	ATF_REQUIRE(devnull >= 0);
	ATF_REQUIRE(pdsetfd(procfd, STDIN_FILENO, devnull, NULL) == 0);
	ATF_REQUIRE(pdsetfd(procfd, STDOUT_FILENO, devnull, NULL) == 0);
	ATF_REQUIRE(pdsetfd(procfd, STDERR_FILENO, devnull, NULL) == 0);

	error = pdexec(procfd, execfd, "", argv, envv, AT_EMPTY_PATH);
	ATF_REQUIRE_MSG(error == 0, "pdexec: %s", strerror(errno));
	ATF_REQUIRE(close(execfd) == 0);
	ATF_REQUIRE(close(dirfd) == 0);
	ATF_REQUIRE(close(devnull) == 0);

	error = pdwait(procfd, &status, WEXITED, NULL, NULL);
	ATF_REQUIRE_MSG(error == 0, "pdwait: %s", strerror(errno));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "shell status %#x", status);

	snprintf(marker, sizeof(marker), "%s/cwdmarker", dir);
	ATF_REQUIRE_MSG(stat(marker, &sb) == 0,
	    "marker not created in the chosen cwd: %s", strerror(errno));

	ATF_REQUIRE(close(procfd) == 0);
	unlink(marker);
	rmdir(dir);
}

/*
 * pdchroot(2) with AT_FDROOT propagates the caller's own root, which needs no
 * privilege; combined with a working directory the embryo then runs.
 */
ATF_TC_WITHOUT_HEAD(chroot_at_fdroot);
ATF_TC_BODY(chroot_at_fdroot, tc)
{
	char *argv[] = { __DECONST(char *, "true"), NULL };
	char *envv[] = { NULL };
	int error, execfd, procfd, status;

	execfd = open_exec("/usr/bin/true");
	procfd = pdembryo_bare();

	error = pdchdir(procfd, AT_FDCWD);
	ATF_REQUIRE_MSG(error == 0, "pdchdir(AT_FDCWD): %s", strerror(errno));
	error = pdchroot(procfd, AT_FDROOT);
	ATF_REQUIRE_MSG(error == 0, "pdchroot(AT_FDROOT): %s", strerror(errno));

	error = pdexec(procfd, execfd, "", argv, envv, AT_EMPTY_PATH);
	ATF_REQUIRE_MSG(error == 0, "pdexec: %s", strerror(errno));
	ATF_REQUIRE(close(execfd) == 0);

	error = pdwait(procfd, &status, WEXITED, NULL, NULL);
	ATF_REQUIRE_MSG(error == 0, "pdwait: %s", strerror(errno));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	ATF_REQUIRE(close(procfd) == 0);
}

/*
 * pdcap_enter(2) puts the embryo in capability mode and, as a side effect,
 * fills in the directories it left unset -- so a bare embryo becomes runnable
 * without an explicit pdchdir()/pdchroot().
 *
 * The program has to be statically linked: in capability mode the run-time
 * linker cannot open shared libraries by path, so a dynamic binary would die
 * in rtld before reaching main().  The /rescue tools are static; skip if
 * /rescue/true is absent.
 */
ATF_TC_WITHOUT_HEAD(cap_enter_fills_dirs);
ATF_TC_BODY(cap_enter_fills_dirs, tc)
{
	char *argv[] = { __DECONST(char *, "true"), NULL };
	char *envv[] = { NULL };
	int error, execfd, procfd, status;

	if (access("/rescue/true", X_OK) != 0)
		atf_tc_skip("no static /rescue/true to run under capsicum");

	execfd = open_exec("/rescue/true");
	procfd = pdembryo_bare();		/* no cwd or root */

	error = pdcap_enter(procfd);
	ATF_REQUIRE_MSG(error == 0, "pdcap_enter: %s", strerror(errno));

	/* The dirs requirement is now satisfied even though we set no dirs. */
	error = pdexec(procfd, execfd, "", argv, envv, AT_EMPTY_PATH);
	ATF_REQUIRE_MSG(error == 0, "pdexec: %s", strerror(errno));
	ATF_REQUIRE(close(execfd) == 0);

	error = pdwait(procfd, &status, WEXITED, NULL, NULL);
	ATF_REQUIRE_MSG(error == 0, "pdwait: %s", strerror(errno));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	ATF_REQUIRE(close(procfd) == 0);
}

/*
 * pdsetfd(2) may narrow the rights installed into the embryo, but never widen
 * them: asking for a right the local descriptor does not hold fails with
 * ENOTCAPABLE, while asking for a subset succeeds.
 */
ATF_TC_WITHOUT_HEAD(setfd_rights);
ATF_TC_BODY(setfd_rights, tc)
{
	cap_rights_t limited, wider, subset;
	char path[] = "/tmp/pdnew_rights.XXXXXX";
	int error, fd, procfd;

	fd = mkstemp(path);
	ATF_REQUIRE_MSG(fd >= 0, "mkstemp: %s", strerror(errno));
	unlink(path);

	/* Restrict the local descriptor to read only. */
	cap_rights_init(&limited, CAP_READ);
	ATF_REQUIRE_MSG(cap_rights_limit(fd, &limited) == 0,
	    "cap_rights_limit: %s", strerror(errno));

	procfd = pdembryo();

	/* Requesting more than the descriptor holds is refused. */
	cap_rights_init(&wider, CAP_READ, CAP_WRITE);
	error = pdsetfd(procfd, 7, fd, &wider);
	ATF_REQUIRE_MSG(error == -1, "pdsetfd should reject widening");
	ATF_REQUIRE_MSG(errno == ENOTCAPABLE,
	    "unexpected errno: %d (%s)", errno, strerror(errno));

	/* Requesting a subset of what it holds is accepted. */
	cap_rights_init(&subset, CAP_READ);
	error = pdsetfd(procfd, 7, fd, &subset);
	ATF_REQUIRE_MSG(error == 0, "pdsetfd (subset rights): %s",
	    strerror(errno));

	ATF_REQUIRE(close(procfd) == 0);
	ATF_REQUIRE(close(fd) == 0);
}

/*
 * pdsetfdrange(2) copies a run of the caller's descriptors into the embryo at
 * the same numbers.  A shell writes to the copied descriptor and we read it
 * back.
 */
ATF_TC_WITHOUT_HEAD(setfdrange);
ATF_TC_BODY(setfdrange, tc)
{
	char buf[128];
	char *argv[] = { __DECONST(char *, "sh"), __DECONST(char *, "-c"),
	    __DECONST(char *, "echo range >&7"), NULL };
	char *envv[] = { NULL };
	int devnull, error, execfd, procfd, status, pipefd[2];
	ssize_t n;

	ATF_REQUIRE(pipe(pipefd) == 0);
	/* Park the pipe's write end at descriptor 7 in the caller. */
	ATF_REQUIRE(dup2(pipefd[1], 7) == 7);
	execfd = open_exec("/bin/sh");
	procfd = pdembryo();

	devnull = open("/dev/null", O_RDWR);
	ATF_REQUIRE(devnull >= 0);
	ATF_REQUIRE(pdsetfd(procfd, STDIN_FILENO, devnull, NULL) == 0);
	ATF_REQUIRE(pdsetfd(procfd, STDOUT_FILENO, devnull, NULL) == 0);
	ATF_REQUIRE(pdsetfd(procfd, STDERR_FILENO, devnull, NULL) == 0);

	/* Copy just descriptor 7 across, at the same number. */
	error = pdsetfdrange(procfd, 7, 8, 0);
	ATF_REQUIRE_MSG(error == 0, "pdsetfdrange: %s", strerror(errno));

	error = pdexec(procfd, execfd, "", argv, envv, AT_EMPTY_PATH);
	ATF_REQUIRE_MSG(error == 0, "pdexec: %s", strerror(errno));
	ATF_REQUIRE(close(execfd) == 0);
	ATF_REQUIRE(close(devnull) == 0);
	ATF_REQUIRE(close(7) == 0);
	ATF_REQUIRE(close(pipefd[1]) == 0);

	n = read(pipefd[0], buf, sizeof(buf) - 1);
	ATF_REQUIRE_MSG(n > 0, "read: %s", strerror(errno));
	buf[n] = '\0';
	ATF_REQUIRE_MSG(strcmp(buf, "range\n") == 0,
	    "unexpected output: '%s'", buf);
	ATF_REQUIRE(close(pipefd[0]) == 0);

	error = pdwait(procfd, &status, WEXITED, NULL, NULL);
	ATF_REQUIRE_MSG(error == 0, "pdwait: %s", strerror(errno));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	ATF_REQUIRE(close(procfd) == 0);
}

/*
 * pdsetfdrange(2) skips close-on-exec descriptors, mirroring what an execve(2)
 * would have discarded: a CLOEXEC descriptor in the range is not copied, so
 * the embryo never receives it.
 */
ATF_TC_WITHOUT_HEAD(setfdrange_skips_cloexec);
ATF_TC_BODY(setfdrange_skips_cloexec, tc)
{
	char buf[128];
	char *argv[] = { __DECONST(char *, "sh"), __DECONST(char *, "-c"),
	    __DECONST(char *, "echo range >&7"), NULL };
	char *envv[] = { NULL };
	int devnull, error, execfd, procfd, status, pipefd[2];
	ssize_t n;

	ATF_REQUIRE(pipe(pipefd) == 0);
	ATF_REQUIRE(dup2(pipefd[1], 7) == 7);
	/* Mark descriptor 7 close-on-exec: pdsetfdrange must skip it. */
	ATF_REQUIRE(fcntl(7, F_SETFD, FD_CLOEXEC) == 0);
	execfd = open_exec("/bin/sh");
	procfd = pdembryo();

	devnull = open("/dev/null", O_RDWR);
	ATF_REQUIRE(devnull >= 0);
	ATF_REQUIRE(pdsetfd(procfd, STDIN_FILENO, devnull, NULL) == 0);
	ATF_REQUIRE(pdsetfd(procfd, STDOUT_FILENO, devnull, NULL) == 0);
	ATF_REQUIRE(pdsetfd(procfd, STDERR_FILENO, devnull, NULL) == 0);

	error = pdsetfdrange(procfd, 7, 8, 0);
	ATF_REQUIRE_MSG(error == 0, "pdsetfdrange: %s", strerror(errno));

	error = pdexec(procfd, execfd, "", argv, envv, AT_EMPTY_PATH);
	ATF_REQUIRE_MSG(error == 0, "pdexec: %s", strerror(errno));
	ATF_REQUIRE(close(execfd) == 0);
	ATF_REQUIRE(close(devnull) == 0);
	ATF_REQUIRE(close(7) == 0);
	ATF_REQUIRE(close(pipefd[1]) == 0);

	/* Descriptor 7 was not copied, so the shell's write to it fails and
	 * the pipe stays empty. */
	n = read(pipefd[0], buf, sizeof(buf));
	ATF_REQUIRE_MSG(n == 0, "pipe should be empty, got %zd bytes", n);
	ATF_REQUIRE(close(pipefd[0]) == 0);

	error = pdwait(procfd, &status, WEXITED, NULL, NULL);
	ATF_REQUIRE_MSG(error == 0, "pdwait: %s", strerror(errno));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) != 0,
	    "shell should have failed writing to a missing fd: %#x", status);

	ATF_REQUIRE(close(procfd) == 0);
}

/*
 * pdsetpgid(2) places the embryo in a process group before it runs.  Asking
 * for a group whose id is the embryo's own pid creates a new group; once the
 * process is running the caller sees it there.
 */
ATF_TC_WITHOUT_HEAD(setpgid_new_group);
ATF_TC_BODY(setpgid_new_group, tc)
{
	char *argv[] = { __DECONST(char *, "cat"), NULL };
	char *envv[] = { NULL };
	int devnull, error, execfd, procfd, status, in_pipe[2];
	pid_t pgid, pid;

	ATF_REQUIRE(pipe(in_pipe) == 0);
	execfd = open_exec("/bin/cat");
	procfd = pdembryo();

	error = pdgetpid(procfd, &pid);
	ATF_REQUIRE_MSG(error == 0, "pdgetpid: %s", strerror(errno));

	/* A new group of its own (pgid == the embryo's pid). */
	error = pdsetpgid(procfd, pid);
	ATF_REQUIRE_MSG(error == 0, "pdsetpgid: %s", strerror(errno));

	/* Keep the child alive by holding the write end of its stdin; give it
	 * a stdout and stderr so cat is not tripped up by missing descriptors. */
	error = pdsetfd(procfd, STDIN_FILENO, in_pipe[0], NULL);
	ATF_REQUIRE_MSG(error == 0, "pdsetfd stdin: %s", strerror(errno));
	ATF_REQUIRE(close(in_pipe[0]) == 0);
	devnull = open("/dev/null", O_RDWR);
	ATF_REQUIRE(devnull >= 0);
	ATF_REQUIRE(pdsetfd(procfd, STDOUT_FILENO, devnull, NULL) == 0);
	ATF_REQUIRE(pdsetfd(procfd, STDERR_FILENO, devnull, NULL) == 0);

	error = pdexec(procfd, execfd, "", argv, envv, AT_EMPTY_PATH);
	ATF_REQUIRE_MSG(error == 0, "pdexec: %s", strerror(errno));
	ATF_REQUIRE(close(execfd) == 0);
	ATF_REQUIRE(close(devnull) == 0);

	pgid = getpgid(pid);
	ATF_REQUIRE_MSG(pgid == pid,
	    "child pgid %d, expected %d", (int)pgid, (int)pid);

	ATF_REQUIRE(close(in_pipe[1]) == 0);	/* EOF -> cat exits 0 */
	error = pdwait(procfd, &status, WEXITED, NULL, NULL);
	ATF_REQUIRE_MSG(error == 0, "pdwait: %s", strerror(errno));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	ATF_REQUIRE(close(procfd) == 0);
}

/*
 * Closing the descriptor of an embryo that was never given an image
 * destroys it; its pid must name neither a live process nor a zombie.
 */
ATF_TC_WITHOUT_HEAD(close_before_exec);
ATF_TC_BODY(close_before_exec, tc)
{
	int error, procfd;
	pid_t pid;

	procfd = pdembryo_bare();

	error = pdgetpid(procfd, &pid);
	ATF_REQUIRE_MSG(error == 0, "pdgetpid: %s", strerror(errno));
	ATF_REQUIRE(pid > 0);

	ATF_REQUIRE(close(procfd) == 0);

	ATF_REQUIRE_MSG(kill(pid, 0) == -1 && errno == ESRCH,
	    "embryo pid %d still present after close (kill: %s)",
	    (int)pid, strerror(errno));
}

/*
 * pdsetfd(2) replacing an already-set descriptor: the last one wins.
 */
ATF_TC_WITHOUT_HEAD(setfd_replace);
ATF_TC_BODY(setfd_replace, tc)
{
	char buf[128];
	char *argv[] = { __DECONST(char *, "echo"),
	    __DECONST(char *, "replaced"), NULL };
	char *envv[] = { NULL };
	int error, execfd, procfd, status, pipe1[2], pipe2[2];
	ssize_t n;

	ATF_REQUIRE(pipe(pipe1) == 0);
	ATF_REQUIRE(pipe(pipe2) == 0);
	execfd = open_exec("/bin/echo");
	procfd = pdembryo();

	error = pdsetfd(procfd, STDOUT_FILENO, pipe1[1], NULL);
	ATF_REQUIRE_MSG(error == 0, "pdsetfd 1: %s", strerror(errno));
	error = pdsetfd(procfd, STDOUT_FILENO, pipe2[1], NULL);
	ATF_REQUIRE_MSG(error == 0, "pdsetfd 2: %s", strerror(errno));
	ATF_REQUIRE(close(pipe1[1]) == 0);
	ATF_REQUIRE(close(pipe2[1]) == 0);

	error = pdexec(procfd, execfd, "", argv, envv, AT_EMPTY_PATH);
	ATF_REQUIRE_MSG(error == 0, "pdexec: %s", strerror(errno));
	ATF_REQUIRE(close(execfd) == 0);

	n = read(pipe1[0], buf, sizeof(buf));
	ATF_REQUIRE_MSG(n == 0, "pipe1 should be empty, got %zd bytes", n);
	ATF_REQUIRE(close(pipe1[0]) == 0);

	n = read(pipe2[0], buf, sizeof(buf) - 1);
	ATF_REQUIRE_MSG(n > 0, "read pipe2: %s", strerror(errno));
	buf[n] = '\0';
	ATF_REQUIRE_MSG(strcmp(buf, "replaced\n") == 0,
	    "unexpected output: '%s'", buf);
	ATF_REQUIRE(close(pipe2[0]) == 0);

	error = pdwait(procfd, &status, WEXITED, NULL, NULL);
	ATF_REQUIRE(error == 0);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	ATF_REQUIRE(close(procfd) == 0);
}

/*
 * A shebang script exec'd by descriptor: its interpreter reaches the script
 * through /dev/fd/N, so fdescfs must be mounted; skip otherwise.
 */
ATF_TC_WITHOUT_HEAD(shebang);
ATF_TC_BODY(shebang, tc)
{
	char buf[128];
	char *argv[] = { __DECONST(char *, "testscript"), NULL };
	char *envv[] = { NULL };
	char scriptpath[] = "/tmp/pdnew_test.XXXXXX";
	int error, execfd, procfd, scriptfd, status, pipefd[2];
	ssize_t n;
	struct statfs sf;

	if (statfs("/dev/fd", &sf) != 0 ||
	    strcmp(sf.f_fstypename, "fdescfs") != 0)
		atf_tc_skip("fdescfs is not mounted at /dev/fd");

	scriptfd = mkstemp(scriptpath);
	ATF_REQUIRE_MSG(scriptfd >= 0, "mkstemp: %s", strerror(errno));
	ATF_REQUIRE(write(scriptfd, "#!/bin/sh\necho shebang\n", 23) == 23);
	ATF_REQUIRE(fchmod(scriptfd, 0755) == 0);
	ATF_REQUIRE(close(scriptfd) == 0);

	ATF_REQUIRE(pipe(pipefd) == 0);
	execfd = open_exec(scriptpath);
	procfd = pdembryo();

	error = pdsetfd(procfd, STDOUT_FILENO, pipefd[1], NULL);
	ATF_REQUIRE_MSG(error == 0, "pdsetfd: %s", strerror(errno));
	ATF_REQUIRE(close(pipefd[1]) == 0);

	error = pdexec(procfd, execfd, "", argv, envv, AT_EMPTY_PATH);
	ATF_REQUIRE_MSG(error == 0, "pdexec: %s", strerror(errno));
	ATF_REQUIRE(close(execfd) == 0);

	n = read(pipefd[0], buf, sizeof(buf) - 1);
	ATF_REQUIRE_MSG(n > 0, "read: %s", strerror(errno));
	buf[n] = '\0';
	ATF_REQUIRE_MSG(strcmp(buf, "shebang\n") == 0,
	    "unexpected output: '%s'", buf);
	ATF_REQUIRE(close(pipefd[0]) == 0);

	error = pdwait(procfd, &status, WEXITED, NULL, NULL);
	ATF_REQUIRE_MSG(error == 0, "pdwait: %s", strerror(errno));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	ATF_REQUIRE(close(procfd) == 0);
	unlink(scriptpath);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, basic_true);
	ATF_TP_ADD_TC(tp, basic_false);
	ATF_TP_ADD_TC(tp, exec_by_path);
	ATF_TP_ADD_TC(tp, setfd_stdout);
	ATF_TP_ADD_TC(tp, setfd_stdin);
	ATF_TP_ADD_TC(tp, error_noexec);
	ATF_TP_ADD_TC(tp, error_bad_procfd);
	ATF_TP_ADD_TC(tp, exec_requires_dirs);
	ATF_TP_ADD_TC(tp, chdir_sets_cwd);
	ATF_TP_ADD_TC(tp, chroot_at_fdroot);
	ATF_TP_ADD_TC(tp, cap_enter_fills_dirs);
	ATF_TP_ADD_TC(tp, setfd_rights);
	ATF_TP_ADD_TC(tp, setfdrange);
	ATF_TP_ADD_TC(tp, setfdrange_skips_cloexec);
	ATF_TP_ADD_TC(tp, setpgid_new_group);
	ATF_TP_ADD_TC(tp, close_before_exec);
	ATF_TP_ADD_TC(tp, setfd_replace);
	ATF_TP_ADD_TC(tp, shebang);

	return (atf_no_error());
}
